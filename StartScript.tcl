# Create the simulator object
set ns [new Simulator]

# Open the NAM trace file
set nf [open out.nam w]
$ns namtrace-all $nf

# Open the output trace file
set f [open out.tr w]
$ns trace-all $f

#####################################################
#       INSERT YOUR NETWORK DEFINTION HERE          #
#####################################################

$ns at 50.0 "finish"

proc finish {} {
    
  # Use the following external variables
  global ns nf f
  $ns flush-trace
	
  # Close the trace files
  close $nf
  close $f 

  # Show on the command line that we are running NAM
  puts "running NAM..."

  # Run NAM with the out.nam file 
  exec nam out.nam &

  exit 0
}

# Run the simulation
$ns run
