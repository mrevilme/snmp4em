module SNMP4EM
  class SnmpTrapd < EventMachine::Connection 
    def receive_data(data)  
      source_port, source_ip = Socket.unpack_sockaddr_in(get_peername)
      begin
        message = SNMP::Message.decode(data, @mib)
        if @manager.community_allowed? message.community
          trap = message.pdu
          if trap.kind_of?(SNMP::InformRequest)
            @transport.send(message.response.encode, source_ip, source_port)
          end
          trap.source_ip = source_ip
          @manager.select_handler(trap).call(trap)
        end
      rescue => e
        puts "Error handling trap: #{e}"
        puts e.backtrace.join("\n")
        puts "Received data:"
        p data
      end
    end

    def initialize(*args)
      super
      @manager = args.first[:manager]
    end
  
  end
end
