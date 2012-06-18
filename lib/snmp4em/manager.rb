# The SNMP4EM library 

module SNMP4EM
  class Manager
    include SNMP4EM::CommonRequests

    #
    # @pending_requests maps a request's id to its SnmpRequest
    #
    @pending_requests = {}
    @socket = nil
    
    class << self
      attr_reader :pending_requests
      attr_reader :socket
      
      def init_socket #:nodoc:
        # When the socket is in error state, close the socket and re-open a new one.
        if !@socket.nil? && @socket.error?
          @socket.close_connection
          @socket = nil
        end

        @socket ||= EM::open_datagram_socket("0.0.0.0", 0, Handler)
      end

      def track_request(request)
        @pending_requests.delete(request.snmp_id)

        begin
          request.snmp_id = rand(2**31)  # Largest SNMP Signed INTEGER
        end while @pending_requests[request.snmp_id]

        @pending_requests[request.snmp_id] = request
      end
    end
    
    attr_reader :host, :port, :timeout, :retries, :version, :community_ro, :community_rw
    
    # Creates a new object to communicate with SNMPv1 agents. Optionally pass in the following parameters:
    # *  _host_ - IP/hostname of remote agent (default: 127.0.0.1)
    # *  _port_ - UDP port on remote agent (default: 161)
    # *  _community_ - Community string to use (default: public)
    # *  _community_ro_ - Read-only community string to use for get/getnext/walk operations (default: public)
    # *  _community_rw_ - Read-write community string to use for set operations (default: public)
    # *  _timeout_ - Number of seconds to wait before a request times out (default: 1)
    # *  _retries_ - Number of retries before failing (default: 3)
    
    def initialize(args = {})
      @host    = args[:host]    || "127.0.0.1"
      @port    = args[:port]    || 161
      @timeout = args[:timeout] || 1
      @retries = args[:retries] || 3
      @version = args[:version] || :SNMPv2c

      self.extend SNMPv2cRequests if @version == :SNMPv2c

      @community_ro = args[:community_ro] || args[:community] || "public"
      @community_rw = args[:community_rw] || args[:community] || "public"
      @cls = args[:class] || SNMP4EM::SnmpTrapd
      
      self.class.init_socket
    end
    
    def send(message) #:nodoc:
      self.class.socket.send_datagram message.encode, @host, @port
    end

    class Trapd < Manager

      def initialize(args = {})
        super
        @port = args[:port]   || 162
        @oid_handler = {}
      end

      class << self
        def init_socket #:nodoc:
        end
      end

      NULL_HANDLER = Proc.new {}

      ##
      # Start socket and listen.
      def start
        EventMachine.open_datagram_socket @host, @port, @cls, :manager => self
      end

      ##
      # Define the default trap handler.  The default trap handler block is
      # executed only if no other block is applicable.  This handler should
      # expect to receive both SNMPv1_Trap and SNMPv2_Trap objects.
      #
      def on_trap_default(&block)
        raise ArgumentError, "a block must be provided" unless block
        @default_handler = block
      end

      ##
      # Define a trap handler block for a specific trap ObjectId.  This handler
      # only applies to SNMPv2 traps.  Note that symbolic OIDs are not
      # supported by this method (like in the SNMP.Manager class).
      #
      def on_trap(object_id, &block)
        raise ArgumentError, "a block must be provided" unless block
        @oid_handler[SNMP::ObjectId.new(object_id)] = block
      end

      ##
      # Define a trap handler block for all SNMPv1 traps.  The trap yielded
      # to the block will always be an SNMPv1_Trap.
      #
      def on_trap_v1(&block)
        raise ArgumentError, "a block must be provided" unless block
        @v1_handler = block
      end


      ##
      # Define a trap handler block for all SNMPv2c traps.  The trap yielded
      # to the block will always be an SNMPv2_Trap.  Note that InformRequest
      # is a subclass of SNMPv2_Trap, so inform PDUs are also received by
      # this handler.
      #
      def on_trap_v2c(&block)
        raise ArgumentError, "a block must be provided" unless block
        @v2c_handler = block
      end

      # Loads external mib modules for utilization.
      def load_modules(module_list, mib_dir)
        module_list.each { |m| @mib.load_module(m, mib_dir) }
      end

      def community_allowed?(msg_community)
        @community.nil? || @community == msg_community || !(Array(@community) & Array(msg_community)).empty?
      end

      def select_handler(trap)
        if trap.kind_of?(SNMP::SNMPv2_Trap)
          oid = trap.trap_oid
          if @oid_handler[oid]
            return @oid_handler[oid]
          elsif @v2c_handler
            return @v2c_handler
          elsif @default_handler
            return @default_handler
          else
            return NULL_HANDLER
          end
        elsif trap.kind_of?(SNMP::SNMPv1_Trap)
          if @v1_handler
            return @v1_handler
          elsif @default_handler
            return @default_handler
          else
            return NULL_HANDLER
          end
        else
          return NULL_HANDLER
        end
      end
    end
  end
end
