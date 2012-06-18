require 'rubygems'
$:.unshift("../lib/")
require 'snmp4em'



trap = SNMP4EM::Manager::Trapd.new(:host => "0.0.0.0")

trap.on_trap "1.11.12.13.14.15", do |trap| 
  puts "Specific trap"
end

trap.on_trap_default do |trap|
  puts "Default trap"
end

EM.run {
  trap.start
}