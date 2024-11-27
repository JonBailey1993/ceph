#include <utility>

#include "include/random.h"

#include "global/global_init.h"
#include "global/global_context.h"

#include "ProgramOptionReader.h"

#include "common/io_exerciser/IoOp.h"
#include "common/io_exerciser/IoSequence.h"
#include "common/io_exerciser/Model.h"

#include "common/split.h"

#include "librados/librados_asio.h"

#include <optional>
#include <string>
#include <utility>

#include <boost/program_options.hpp>

#include "erasure-code/ErasureCodePlugin.h"

/* Overview
 *
 * class ProgramOptionSelector
 *   Base class for selector objects below with common code for 
 *   selecting options
 * 
 * class SelectObjectSize
 *   Selects min and max object sizes for a test
 *
 * class SelectErasureKM
 *   Selects an EC k and m value for a test
 * 
 * class SelectErasurePlugin
 *   Selects an plugin for a test
 * 
 * class SelectErasurePool
 *   Selects an EC pool (plugin,k and m) for a test. Also creates the
 *   pool as well.
 *
 * class SelectBlockSize
 *   Selects a block size for a test
 *
 * class SelectNumThreads
 *   Selects number of threads for a test
 *
 * class SelectSeqRange
 *   Selects a sequence or range of sequences for a test
 *
 * class TestObject
 *   Runs a test against an object, generating IOSequence
 *   and applying them to an IoExerciser
 *
 * main
 *   Run sequences of I/O with data integrity checking to
 *   one or more objects in parallel. Without arguments
 *   runs a default configuration against one object.
 *   Command arguments can select alternative
 *   configurations. Alternatively running against
 *   multiple objects with --objects <n> will select a
 *   random configuration for all but the first object.
 */

namespace po = boost::program_options;

namespace ceph
{
  class ErasureCodePlugin;

  namespace io_sequence::tester
  {
    // Choices for min and max object size
    inline static constexpr size_t objectSizeSize = 10;
    inline static constexpr std::array<std::pair<int,int>,objectSizeSize>
      objectSizeChoices =
    {{
      {1,32},  // Default - best for boundary checking
      {12,14},
      {28,30},
      {36,38},
      {42,44},
      {52,54},
      {66,68},
      {72,74},
      {83,83},
      {97,97}
    }};

    using SelectObjectSize = ProgramOptionSelector<std::pair<int, int>,
                                                   io_sequence::tester
                                                    ::objectSizeSize,
                                                   io_sequence::tester
                                                    ::objectSizeChoices>;

    // Choices for block size
    inline static constexpr int blockSizeSize = 5;
    inline static constexpr std::array<uint64_t, blockSizeSize> blockSizeChoices =
    {{
      2048, // Default - test boundaries for EC 4K chunk size
      512,
      3767,
      4096,
      32768
    }};

    using SelectBlockSize = ProgramOptionSelector<uint64_t,
                                                  io_sequence::tester
                                                    ::blockSizeSize,
                                                  io_sequence::tester
                                                    ::blockSizeChoices>;

    // Choices for number of threads
    inline static constexpr int threadArraySize = 4;
    inline static constexpr std::array<int, threadArraySize> threadCountChoices =
    {{
      1, // Default
      2,
      4,
      8
    }};

    using SelectNumThreads = ProgramOptionSelector<int,
                                                   io_sequence::tester
                                                    ::threadArraySize,
                                                   io_sequence::tester
                                                    ::threadCountChoices>;

    class SelectSeqRange : public ProgramOptionReader<std::pair<ceph::io_exerciser
                                                                  ::Sequence,
                                                                ceph::io_exerciser
                                                                  ::Sequence>>
    {
      public:
        SelectSeqRange(po::variables_map& vm);
        const std::pair<ceph::io_exerciser::Sequence,
                        ceph::io_exerciser::Sequence> select() override;
    };

    // Choices for plugin
    inline static constexpr int pluginListSize = 5;
    inline static constexpr std::array<std::string_view, pluginListSize>
      pluginChoices =
    {{
        "jerasure",
        "isa",
        "clay",
        "shec",
        "lrc"
    }};

    using SelectErasurePlugin = ProgramOptionSelector<std::string_view,
                                                  io_sequence::tester
                                                    ::pluginListSize,
                                                  io_sequence::tester
                                                    ::pluginChoices>;

    class SelectErasureKM : public ProgramOptionGeneratedSelector<std::pair<int,
                                                                            int>>
    {
      public:
        SelectErasureKM(ceph::util::random_number_generator<int>& rng,
                        po::variables_map& vm,
                        std::string_view plugin,
                        std::optional<std::string> technique,
                        bool first_use);

        const std::vector<std::pair<int, int>> generate_selections() override;

      private:
        ceph::util::random_number_generator<int>& rng;

        std::string_view plugin;
        std::optional<std::string> technique;
    };

    class SelectErasurePacketSize :
      public ProgramOptionGeneratedSelector<uint64_t>
    {
      public:
        SelectErasurePacketSize(ceph::util::random_number_generator<int>& rng,
                                po::variables_map& vm,
                                std::string_view plugin,
                                std::optional<std::string_view> technique,
                                std::optional<std::pair<int,int>> km,
                                bool first_use);

        const std::vector<uint64_t> generate_selections() override;

      private:
        ceph::util::random_number_generator<int>& rng;

        std::string_view plugin;
        std::optional<std::string_view> technique;
        std::optional<std::pair<int,int>> km;
    };

    class SelectErasureC : public ProgramOptionGeneratedSelector<uint64_t>
    {
      public:
        SelectErasureC(ceph::util::random_number_generator<int>& rng,
                                po::variables_map& vm,
                                std::string_view plugin,
                                std::optional<std::pair<int,int>> km,
                                bool first_use);

        const std::vector<uint64_t> generate_selections() override;

      private:
        ceph::util::random_number_generator<int>& rng;

        std::string_view plugin;
        std::optional<std::pair<int,int>> km;
    };

    class SelectErasureW : public ProgramOptionGeneratedSelector<uint64_t>
    {
      public:
        SelectErasureW(ceph::util::random_number_generator<int>& rng,
                       po::variables_map& vm,
                       std::string_view plugin,
                       std::optional<std::string_view> technique,
                       std::optional<std::pair<int,int>> km,
                       std::optional<uint64_t> packetsize,
                       bool first_use);

        const std::vector<uint64_t> generate_selections() override;

      private:
        ceph::util::random_number_generator<int>& rng;

        std::string_view plugin;
        std::optional<std::string_view> technique;
        std::optional<std::pair<int,int>> km;
        std::optional<uint64_t> packetsize;
    };

    class SelectErasureTechnique : public ProgramOptionGeneratedSelector<std::string>
    {
      public:
        SelectErasureTechnique(ceph::util::random_number_generator<int>& rng,
                               po::variables_map& vm,
                               std::string_view plugin,
                               bool first_use);

        const std::vector<std::string> generate_selections() override;

      private:
        ceph::util::random_number_generator<int>& rng;

        std::string_view plugin;
    };

    namespace lrc
    {
      // Choices for lrc mappings and layers
      inline static constexpr int mappingLayerListSize = 15;
      inline static constexpr std::array<std::pair<std::string_view, std::string_view>,
                                            mappingLayerListSize>
        mappingLayerChoices =
      {{
        { "_DD", "[[\"cDD\",\"\"]]" },
        { "_DDD", "[[\"cDDD\",\"\"]]" },
        { "_DDDD", "[[\"cDDDD\",\"\"]]" },
        { "_DDDDD", "[[\"cDDDDD\",\"\"]]" },
        { "_DDDDDD", "[[\"cDDDDDD\",\"\"]]" },
        { "_D_D", "[[\"cDcD\",\"\"]]" },
        { "_D_DD", "[[\"cDcDD\",\"\"]]" },
        { "_D_DDD", "[[\"cDcDDD\",\"\"]]" },
        { "_D_DDDD", "[[\"cDcDDDD\",\"\"]]" },
        { "_D_DDDDD", "[[\"cDcDDDDD\",\"\"]]" },
        { "_D_D_", "[[\"cDcDc\",\"\"]]" },
        { "_D_D_D", "[[\"cDcDcD\",\"\"]]" },
        { "_D_D_DD", "[[\"cDcDcDD\",\"\"]]" },
        { "_D_D_DDD", "[[\"cDcDcDDD\",\"\"]]" },
        { "_D_D_DDDD", "[[\"cDcDcDDDD\",\"\"]]" },
      }};

      using SelectMappingAndLayers = ProgramOptionSelector<std::pair<std::string_view,
                                                                     std::string_view>,
                                                           io_sequence::tester
                                                            ::lrc
                                                            ::mappingLayerListSize,
                                                           io_sequence::tester
                                                            ::lrc
                                                            ::mappingLayerChoices>;
    }

    class SelectErasureChunkSize : public ProgramOptionGeneratedSelector<uint64_t>
    {
      public:
        SelectErasureChunkSize(ceph::util::random_number_generator<int>& rng,
                               po::variables_map& vm,
                               ErasureCodeInterfaceRef ec_impl,
                               bool first_use);
        const std::vector<uint64_t> generate_selections() override;

      private:
        ceph::util::random_number_generator<int>& rng;

        ErasureCodeInterfaceRef ec_impl;
    };

    // TODO: Change this to use the map, similar to how the actual plugs store this information
    struct Profile
    {
      std::string name;
      std::string_view plugin;
      std::optional<std::string> technique;
      std::optional<std::pair<int,int>> km;
      std::optional<uint64_t> packet_size;
      std::optional<int> c;
      std::optional<int> w;
      std::optional<std::string_view> mapping;
      std::optional<std::string_view> layers;
      std::optional<uint64_t> chunk_size;
      std::optional<bool> jerasure_per_chunk_alignment;
    };

    class SelectErasureProfile : public ProgramOptionReader<Profile>
    {
      public:
        SelectErasureProfile(boost::intrusive_ptr<CephContext> cct,
                             ceph::util::random_number_generator<int>& rng,
                             po::variables_map& vm,
                             librados::Rados& rados,
                             bool dry_run,
                             bool first_use);
        const Profile select() override;
        void create(Profile profile);
        const Profile selectExistingProfile(const std::string& profile_name);

      private:
        boost::intrusive_ptr<CephContext> cct;
        librados::Rados& rados;
        bool dry_run;
        ceph::util::random_number_generator<int>& rng;
        po::variables_map& vm;

        bool first_use;

        SelectErasurePlugin spl;
        lrc::SelectMappingAndLayers sml;

        std::unique_ptr<ErasureCodePlugin> erasureCode;
    };

    class SelectErasurePool : public ProgramOptionReader<std::string>
    {
      public:
        SelectErasurePool(boost::intrusive_ptr<CephContext> cct,
                          ceph::util::random_number_generator<int>& rng,
                          po::variables_map& vm,
                          librados::Rados& rados,
                          bool dry_run,
                          bool allow_pool_autoscaling,
                          bool allow_pool_balancer,
                          bool allow_pool_deep_scrubbing,
                          bool allow_pool_scrubbing,
                          bool test_recovery);
        const std::string select() override;
        std::string create();
        void configureServices(bool allow_pool_autoscaling,
                               bool allow_pool_balancer,
                               bool allow_pool_deep_scrubbing,
                               bool allow_pool_scrubbing,
                               bool test_recovery);

        inline bool get_allow_pool_autoscaling() { return allow_pool_autoscaling; }
        inline bool get_allow_pool_balancer() { return allow_pool_balancer; }
        inline bool get_allow_pool_deep_scrubbing() { return allow_pool_deep_scrubbing; }
        inline bool get_allow_pool_scrubbing() { return allow_pool_scrubbing; }

        inline std::optional<Profile> getProfile() { return profile; }

      private:
        librados::Rados& rados;
        bool dry_run;

        bool allow_pool_autoscaling;
        bool allow_pool_balancer;
        bool allow_pool_deep_scrubbing;
        bool allow_pool_scrubbing;
        bool test_recovery;

        bool first_use;

        SelectErasureProfile sep;

        std::optional<Profile> profile;
    };

    class TestObject
    {
    public:
      TestObject( const std::string oid,
                  librados::Rados& rados,
                  boost::asio::io_context& asio,
                  ceph::io_sequence::tester::SelectBlockSize& sbs,
                  ceph::io_sequence::tester::SelectErasurePool& spl,
                  ceph::io_sequence::tester::SelectObjectSize& sos,
                  ceph::io_sequence::tester::SelectNumThreads& snt,
                  ceph::io_sequence::tester::SelectSeqRange& ssr,
                  ceph::util::random_number_generator<int>& rng,
                  ceph::mutex& lock,
                  ceph::condition_variable& cond,
                  bool dryrun,
                  bool verbose,
                  std::optional<int>  seqseed,
                  bool testRecovery);

      int get_num_io();
      bool readyForIo();
      bool next();
      bool finished();

    protected:
      std::unique_ptr<ceph::io_exerciser::Model> exerciser_model;
      std::pair<int,int> obj_size_range;
      std::pair<ceph::io_exerciser::Sequence,
                ceph::io_exerciser::Sequence> seq_range;
      ceph::io_exerciser::Sequence curseq;
      std::unique_ptr<ceph::io_exerciser::IoSequence> seq;
      std::unique_ptr<ceph::io_exerciser::IoOp> op;
      bool done;
      ceph::util::random_number_generator<int>& rng;
      bool verbose;
      std::optional<int> seqseed;
      std::optional<std::pair<int, int>> poolKM;
      std::optional<std::pair<std::string_view,
                              std::string_view>> poolMappingLayers;
      bool testrecovery;
    };

    class TestRunner
    {
    public:
      TestRunner(boost::intrusive_ptr<CephContext> cct,
                 po::variables_map& vm,
                 librados::Rados& rados);
      ~TestRunner();

      bool run_test();

    private:
      librados::Rados& rados;
      int seed;
      ceph::util::random_number_generator<int> rng;

      ceph::io_sequence::tester::SelectBlockSize sbs;
      ceph::io_sequence::tester::SelectObjectSize sos;
      ceph::io_sequence::tester::SelectErasurePool spo;
      ceph::io_sequence::tester::SelectNumThreads snt;
      ceph::io_sequence::tester::SelectSeqRange ssr;

      boost::asio::io_context asio;
      std::thread thread;
      std::optional<boost::asio::executor_work_guard<
                    boost::asio::io_context::executor_type>> guard;
      ceph::mutex lock = ceph::make_mutex("RadosIo::lock");
      ceph::condition_variable cond;

      bool input_valid;

      bool verbose;
      bool dryrun;
      std::optional<int> seqseed;
      bool interactive;

      bool testrecovery;

      bool allow_pool_autoscaling;
      bool allow_pool_balancer;
      bool allow_pool_deep_scrubbing;
      bool allow_pool_scrubbing;

      bool show_sequence;
      bool show_help;

      int num_objects;
      std::string object_name;

      std::string line;
      ceph::split split = ceph::split("");
      ceph::spliterator tokens;

      void clear_tokens();
      std::string get_token(bool allow_eof = false);
      std::optional<std::string> get_optional_token();
      uint64_t get_numeric_token();
      std::optional<uint64_t> get_optional_numeric_token();

      bool run_automated_test();

      bool run_interactive_test();

      void help();
      void list_sequence(bool testrecovery);
    };
  }
}