# Create the simulator object
set ns [new Simulator]

# Open the NAM trace file
set nf [open best_effort.nam w]
$ns namtrace-all $nf

# Open the output trace file
set f [open best_effort.tr w]
$ns trace-all $f

#####################################################
#       INSERT YOUR NETWORK DEFINITION HERE          #
#####################################################
# Nodes
set src1 [$ns node]
$src1 color blue
set src2 [$ns node]
$src2 color blue
set edge1 [$ns node]
$edge1 color blue
set edge2 [$ns node]
$edge2 color blue
set core [$ns node]
$core color blue
set dest1 [$ns node]
$dest1 color blue
set dest2 [$ns node]
$dest2 color blue
# Links
# $ns duplex-link-op color blue
$ns duplex-link $src1 $edge1 5Mb 1ms DropTail
$ns duplex-link-op $src1 $edge1 orient right-down
$ns duplex-link $src2 $edge1 5Mb 1ms DropTail
$ns duplex-link-op $src2 $edge1 orient right-up
$ns duplex-link $edge2 $dest1 5Mb 1ms DropTail
$ns duplex-link-op $edge2 $dest1 orient right-up
$ns duplex-link $edge2 $dest2 5Mb 1ms DropTail
$ns duplex-link-op $edge2 $dest2 orient right-down
$ns duplex-link $edge1 $core 5Mb 1ms DropTail
$ns duplex-link-op $edge1 $core orient right
$ns duplex-link $core $edge2 3Mb 1ms DropTail
$ns queue-limit $core $edge2 10
$ns duplex-link-op $core $edge2 orient right
# Create traffic
# CBR
set udpsource [new Agent/UDP]
set udpsink [new Agent/Null]
$ns attach-agent $src1 $udpsource
$ns attach-agent $dest1 $udpsink
$ns connect $udpsource $udpsink
set cbr [new Application/Traffic/CBR]
$cbr set packetSize_ 500
$cbr set interval_ 0.002
$cbr attach-agent $udpsource
$ns at 1.0 "$cbr start"
$ns at 45.0 "$cbr stop"
# FTP
set tcpsource [new Agent/TCP/Newreno]
set tcpsink [new Agent/TCPSink]
$ns attach-agent $src2 $tcpsource
$ns attach-agent $dest2 $tcpsink
$ns connect $tcpsource $tcpsink
set ftp [new Application/FTP]
$ftp attach-agent $tcpsource
$ns at 5.0 "$ftp send 2097152"

$ns at 50.0 "finish"

proc finish {} {
    
  # Use the following external variables
  global ns nf f
  $ns flush-trace
	
  # Close the trace files
  close $nf
  close $f 

  # Show on the command line that we are running NAM
  # puts "running NAM..."

  # Run NAM with the out.nam file 
  # exec nam $nf &

  exit 0
}

# Run the simulation
$ns run

