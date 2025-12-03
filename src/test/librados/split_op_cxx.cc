#include <future>
#include <boost/asio/io_context.hpp>
#include <common/perf_counters_collection.h>

#include "test/librados/test_cxx.h"
#include "test/librados/testcase_cxx.h"
#include "crimson_utils.h"
#include "cls/fifo/cls_fifo_ops.h"
#include "cls/version/cls_version_ops.h"
#include "common/ceph_json.h"
#include "common/json/ConfigStructures.h"
#include "common/json/OSDStructures.h"

using namespace std;
using namespace librados;

typedef RadosTestPP LibRadosSplitOpPP;
typedef RadosTestECPP LibRadosSplitOpECPP;

// After a write is committed, it isn't necessarily true that the log is
// committed. We do a read of the written area, which allows us to be
// sure that the shards have all received the message that the log can be
// committed, allowing us to test split ops with certainty that it won't be
// bounced due to unstability.
void RadosTestPPBase::ensure_log_committed(const char* oid, uint64_t offset, uint64_t length) {
  ObjectReadOperation read;
  read.read(offset, length, NULL, NULL);

  bufferlist bl;
  int rc = ioctx.operate(oid, &read, &bl);
  ASSERT_EQ(0, rc);
}

TEST_P(LibRadosSplitOpECPP, ReadWithVersion) {
  SKIP_IF_CRIMSON();
  bufferlist bl;
  bl.append("ceph");
  ObjectWriteOperation write1;
  write1.write(0, bl);
  ASSERT_TRUE(AssertOperateWithoutSplitOp(0, "foo", &write1));

  ObjectReadOperation read;
  read.read(0, bl.length(), NULL, NULL);

  bufferlist exec_inbl, exec_outbl;
  int exec_rval;
  read.exec("version", "read", exec_inbl, &exec_outbl, &exec_rval);
  ASSERT_TRUE(AssertOperateWithSplitOp(0, "foo", &read, &bl, librados::OPERATION_BALANCE_READS));
  ASSERT_EQ(0, memcmp(bl.c_str(), "ceph", 4));
  ASSERT_EQ(0, exec_rval);
  cls_version_read_ret exec_version;
  auto iter = exec_outbl.cbegin();
  decode(exec_version, iter);
  ASSERT_EQ(0, exec_version.objv.ver);
  ASSERT_EQ("", exec_version.objv.tag);
}

TEST_P(LibRadosSplitOpECPP, SmallRead) {
  SKIP_IF_CRIMSON();
  bufferlist bl;
  bl.append("ceph");
  ObjectWriteOperation write1;
  write1.write(0, bl);
  ASSERT_TRUE(AssertOperateWithoutSplitOp(0, "foo", &write1));

  ioctx.set_no_version_on_read(true);
  ObjectReadOperation read;
  read.read(0, bl.length(), NULL, NULL);
  ASSERT_TRUE(AssertOperateWithSplitOp(0, "foo", &read, &bl, librados::OPERATION_BALANCE_READS));
  ioctx.set_no_version_on_read(false);
}

TEST_P(LibRadosSplitOpECPP, ReadTwoShards) {
  SKIP_IF_CRIMSON();
  bufferlist bl;
  bl.append_zero(8*1024);
  ObjectWriteOperation write1;
  write1.write(0, bl);
  ASSERT_TRUE(AssertOperateWithoutSplitOp(0, "foo", &write1));
  
  ensure_log_committed("foo", 0, bl.length());

  ioctx.set_no_version_on_read(true);
  ObjectReadOperation read;
  read.read(0, bl.length(), NULL, NULL);
  ASSERT_TRUE(AssertOperateWithSplitOp(0, 2, "foo", &read, &bl, librados::OPERATION_BALANCE_READS));
  ioctx.set_no_version_on_read(false);
}

TEST_P(LibRadosSplitOpECPP, ReadSecondShard) {
  SKIP_IF_CRIMSON();
  bufferlist bl;
  bl.append_zero(8*1024);
  ObjectWriteOperation write1;
  write1.write(0, bl);
  ASSERT_TRUE(AssertOperateWithoutSplitOp(0, "foo", &write1));
  
  ensure_log_committed("foo", 0, bl.length());

  ioctx.set_no_version_on_read(true);
  ObjectReadOperation read;
  read.read(4*1024, 4*1024, NULL, NULL);
  ASSERT_TRUE(AssertOperateWithSplitOp(0, "foo", &read, &bl, librados::OPERATION_BALANCE_READS));
  ioctx.set_no_version_on_read(false);
}

TEST_P(LibRadosSplitOpECPP, ReadSecondShardWithVersion) {
  SKIP_IF_CRIMSON();
  bufferlist bl;
  bl.append_zero(8*1024);
  ObjectWriteOperation write1;
  write1.write(0, bl);
  ASSERT_TRUE(AssertOperateWithoutSplitOp(0, "foo", &write1));

  ensure_log_committed("foo", 0, bl.length());

  ObjectReadOperation read;
  read.read(4*1024, 4*1024, NULL, NULL);
  ASSERT_TRUE(AssertOperateWithSplitOp(0, 2, "foo", &read, &bl, librados::OPERATION_BALANCE_READS));
}

TEST_P(LibRadosSplitOpECPP, ReadWithIllegalClsOp) {
  SKIP_IF_CRIMSON();
  bufferlist bl;
  bl.append("ceph");
  ObjectWriteOperation write1;
  write1.write(0, bl);
  ASSERT_TRUE(AssertOperateWithoutSplitOp(0, "foo", &write1));

  bufferlist new_bl;
  new_bl.append("CEPH");
  ObjectWriteOperation write2;
  bufferlist exec_inbl, exec_outbl;
  int exec_rval;
  rados::cls::fifo::op::init_part op;
  encode(op, exec_inbl);
  write2.exec("fifo", "init_part", exec_inbl, &exec_outbl, &exec_rval);
  ASSERT_TRUE(AssertOperateWithoutSplitOp(-EOPNOTSUPP, "foo", &write2));
}

TEST_P(LibRadosSplitOpECPP, XattrReads) {
  SKIP_IF_CRIMSON();
  bufferlist bl, attr_bl, attr_read_bl;
  std::string attr_key = "my_key";
  std::string attr_value = "my_attr";

  bl.append("ceph");
  ObjectWriteOperation write1;
  write1.write(0, bl);
  encode(attr_value, attr_bl);
  write1.setxattr(attr_key.c_str(), attr_bl);
  ASSERT_TRUE(AssertOperateWithoutSplitOp(0, "foo", &write1));

  ObjectReadOperation read;
  read.read(0, bl.length(), NULL, NULL);

  int getxattr_rval, getxattrs_rval;
  read.getxattr(attr_key.c_str(), &attr_read_bl, &getxattr_rval);
  std::map<string, bufferlist> pattrs{ {"", {}}, {attr_key, {}}};
  read.getxattrs(&pattrs, &getxattrs_rval);
  read.cmpxattr(attr_key.c_str(), CEPH_OSD_CMPXATTR_OP_EQ, attr_bl);

  ASSERT_TRUE(AssertOperateWithSplitOp(1, "foo", &read, &bl, librados::OPERATION_BALANCE_READS));
  ASSERT_EQ(0, memcmp(bl.c_str(), "ceph", 4));
  ASSERT_EQ(0, getxattr_rval);
  ASSERT_EQ(0, getxattrs_rval);
}

TEST_P(LibRadosSplitOpECPP, Stat) {
  SKIP_IF_CRIMSON();
  bufferlist bl, attr_bl, attr_read_bl;
  std::string attr_key = "my_key";
  std::string attr_value = "my_attr";

  bl.append("ceph");
  ObjectWriteOperation write1;
  write1.write(0, bl);
  encode(attr_value, attr_bl);
  write1.setxattr(attr_key.c_str(), attr_bl);
  ASSERT_TRUE(AssertOperateWithoutSplitOp(0, "foo", &write1));

  ObjectReadOperation read;
  read.read(0, bl.length(), NULL, NULL);

  uint64_t size;
  timespec time;
  time.tv_nsec = 0;
  time.tv_sec = 0;
  int stat_rval;
  read.stat2(&size, &time, &stat_rval);

  ASSERT_TRUE(AssertOperateWithSplitOp(0, "foo", &read, &bl, librados::OPERATION_BALANCE_READS));
  ASSERT_EQ(0, memcmp(bl.c_str(), "ceph", 4));
  ASSERT_EQ(0, stat_rval);
  ASSERT_EQ(4, size);
  ASSERT_NE(0, time.tv_nsec);
  ASSERT_NE(0, time.tv_sec);
}

std::string RadosTestPPBase::get_bluestore_debug_inject_read_err() {
  int rc;
  bufferlist outbl;
  auto f = std::make_unique<JSONFormatter>(false);

  std::string  bluestore_debug_inject_read_err_value;
  ceph::messaging::config::ConfigGetRequest get_config_bluestore_debug_request{
    "osd", "bluestore_debug_inject_read_err"};
  std::ostringstream oss;
  encode_json("ConfigGetRequest", get_config_bluestore_debug_request, f.get());
  f->flush(oss);
  rc = cluster.mon_command(oss.str(), {}, &outbl, NULL);
  ceph_assert(rc == 0);

  bluestore_debug_inject_read_err_value = outbl.to_str();
  bluestore_debug_inject_read_err_value.erase(
  std::remove_if(bluestore_debug_inject_read_err_value.begin(),
                 bluestore_debug_inject_read_err_value.end(),
                 ::isspace));

  return bluestore_debug_inject_read_err_value;
}

void RadosTestPPBase::set_bluestore_debug_inject_read_err(std::string value) {
  int rc;
  bufferlist outbl;
  auto f = std::make_unique<JSONFormatter>(false);

  ceph::messaging::config::ConfigSetRequest set_config_bluestore_debug_request{
    "osd", "bluestore_debug_inject_read_err", value};
  std::ostringstream oss;
  encode_json("ConfigSetRequest", set_config_bluestore_debug_request, f.get());
  f->flush(oss);
  rc = cluster.mon_command(oss.str(), {}, &outbl, NULL);
  ASSERT_EQ(rc, 0);
}

int RadosTestPPBase::get_acting_primary_osd(const std::string& pool_name,
                                            const std::string& oid) {
  int rc;
  bufferlist outbl;
  auto f = std::make_unique<JSONFormatter>(false);

  ceph::messaging::osd::OSDMapRequest osdMapRequest{pool_name, oid, ""};
  std::ostringstream oss;
  encode_json("OSDMapRequest", osdMapRequest, f.get());
  f->flush(oss);
  rc = cluster.mon_command(oss.str(), {}, &outbl, NULL);
  ceph_assert(rc == 0);

  JSONParser p;
  bool success = p.parse(outbl.c_str(), outbl.length());
  ceph_assert(success);

  ceph::messaging::osd::OSDMapReply reply;
  reply.decode_json(&p);

  return reply.acting_primary;
}

int RadosTestPPBase::get_osd_for_shard(const std::string& pool_name,
                                            const std::string& oid,
                                            int shard_index) {
  int rc;
  bufferlist outbl;
  auto f = std::make_unique<JSONFormatter>(false);

  ceph::messaging::osd::OSDMapRequest osdMapRequest{pool_name, oid, ""};
  std::ostringstream oss;
  encode_json("OSDMapRequest", osdMapRequest, f.get());
  f->flush(oss);
  rc = cluster.mon_command(oss.str(), {}, &outbl, NULL);
  ceph_assert(rc == 0);

  JSONParser p;
  bool success = p.parse(outbl.c_str(), outbl.length());
  ceph_assert(success);

  ceph::messaging::osd::OSDMapReply reply;
  reply.decode_json(&p);

  return reply.acting.at(shard_index);
}

void RadosTestPPBase::inject_read_delay(const std::string& pool_name,
                                        const std::string& oid,
                                        int primary_osd, int shard_index,
                                        uint64_t type, uint64_t when,
                                        uint64_t duration) {
  int rc;
  bufferlist outbl;
  auto f = std::make_unique<JSONFormatter>(false);

  messaging::osd::InjectECErrorRequest<io_exerciser::InjectOpType::ReadDelayed>
    injectErrorRequest{pool_name, oid, shard_index, type, when, duration};

  std::ostringstream oss;
  encode_json("InjectECErrorRequest", injectErrorRequest, f.get());
  f->flush(oss);
  rc = cluster.osd_command(primary_osd, oss.str(), {}, &outbl, NULL);
  ASSERT_EQ(rc, 0);
}

void RadosTestPPBase::clear_read_delay_inject(const std::string& pool_name,
                                              const std::string& oid,
                                              int primary_osd, int shard_index,
                                              uint64_t type) {
  int rc;
  bufferlist outbl;
  auto f = std::make_unique<JSONFormatter>(false);

  messaging::osd::InjectECClearErrorRequest<io_exerciser::InjectOpType::ReadDelayed>
    injectErrorRequest{pool_name, oid, shard_index, type};

  std::ostringstream oss;
  encode_json("InjectECClearErrorRequest", injectErrorRequest, f.get());
  f->flush(oss);
  rc = cluster.osd_command(primary_osd, oss.str(), {}, &outbl, NULL);
  ASSERT_EQ(rc, 0);
}

TEST_P(LibRadosSplitOpECPP, TestECDirectReadTornWriteProtection) {
  // Param 1: Fast_EC enabled
  // Param 2: Split OPs enabled
  bufferlist outbl;
  auto f = std::make_unique<JSONFormatter>(false);

  // Get original bluestore_debug_inject_read_err value
  std::string original_bluestore_debug_inject_read_err_value
    = get_bluestore_debug_inject_read_err();

  // Set the value needed for this test
  set_bluestore_debug_inject_read_err("true");

  ASSERT_EQ(get_bluestore_debug_inject_read_err(), "true");

  // Create object in pool
  bufferlist bl;
  bl.append_zero(8*1024);
  ObjectWriteOperation write1;
  write1.write(0, bl);
  ASSERT_TRUE(AssertOperateWithoutSplitOp(0, "foo", &write1));

  ensure_log_committed("foo", 0, bl.length());

  int acting_primary = get_acting_primary_osd(pool_name, "foo");

  std::cout << "Injecting delay on shard 1" << std::endl;
  inject_read_delay(pool_name, ioctx.get_namespace() + "/foo", acting_primary, 1, 2, 0,
                       std::numeric_limits<int64_t>::max());

  // Perform a write that will be delayed
  bufferlist bl_overwrite;
  char buffer[8*1024];
  for (int i = 0; i < 8*1024; i++) {
    buffer[i] = 0xff;
  }
  bufferptr bp(buffer, 8*1024);
  bl_overwrite.append(bp);
  std::cout << "Sending overwrite" << std::endl;
  ObjectWriteOperation write2;
  write1.write(0, bl_overwrite);
  ASSERT_TRUE(OperateWithoutSplitOp(0, "foo", &write2));

  auto op_send_stat = "objecter.op_send"sv;
  uint64_t before_op_send_count = get_perf_counter_by_path(op_send_stat);
  std::cout << "Before " << op_send_stat << " == " << before_op_send_count << std::endl;

  // Perform a read that will overtake the write
  auto send_read = [this, length = bl_overwrite.length()]() {
    std::cout << "Sending read" << std::endl;
    ObjectReadOperation read;
    read.read(0, length, NULL, NULL);
    bufferlist bl_read;
    AssertOperateWithSplitOp(0, "foo", &read, &bl_read, librados::OPERATION_BALANCE_READS);
    return bl_read;
  };

  future<bufferlist> future_bl_read = std::async(std::launch::async, send_read);

  uint64_t op_send_count = get_perf_counter_by_path(op_send_stat);
  while (op_send_count != before_op_send_count + 2) {
    op_send_count = get_perf_counter_by_path(op_send_stat);
    std::cout << op_send_stat << " == " << op_send_count << " should be (" << before_op_send_count+2 << ")" << std::endl;
    sleep(1);
  }

  // Clear inject
  std::cout << "Clearing inject" << std::endl;
  clear_read_delay_inject(pool_name, ioctx.get_namespace() + "/foo", acting_primary, 1, 2);

  // Set bluestore_debug_inject_read_err back to its original value
  set_bluestore_debug_inject_read_err(original_bluestore_debug_inject_read_err_value);

  bufferlist bl_read = future_bl_read.get();

  std::cout << "bl_overwrite: ";
  for (int i = 0; i < 8*1024; i++) {
    std::cout << "0x" << std::hex << std::setw(2) << std::setfill('0') << (unsigned int)(unsigned char)bl_overwrite[i] << ", ";
  }
  std::cout << std::endl;
  std::cout << "bl_read: ";
  for (int i = 0; i < 8*1024; i++) {
    std::cout << "0x" << std::hex << std::setw(2) << std::setfill('0') << (unsigned int)(unsigned char)bl_read[i] << ", ";
  }
  std::cout << std::endl;

  std::cout << bl_overwrite.to_str() << std::endl;
  std::cout << bl_read.to_str() << std::endl;

  ASSERT_EQ(bl_read, bl_overwrite);
}

TEST_F(LibRadosSplitOpPP, TestReplicaDirectReadTornWriteProtection) {
  FAIL();
}

INSTANTIATE_TEST_SUITE_P_EC(LibRadosSplitOpECPP);