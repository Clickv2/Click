Made By Lorin Teugels and Sam Mylle
University of Antwerp



This section will describe the elements we made and how they are used.

In the client compound element, you'll see the InterfaceElement.
It has one input and 2 outputs:
	- output 0 if the input packet is IGMP and the interface listens to that multicast address
	- output 1 if the state of the interface has changed or if a report is requested by receiving a query
You'll be able to join or leave a certain multicast address by calling a handler as follows:
write clientxx/interface.Join x.x.x.x
Where the current multicast address is set to 230.0.0.1

In the router, you'll see a RouterInterface element.
It has one input and three outputs.
	- Output 0 is to send IGMP queries
	- Output 1 is to forward the IGMP packets (not messages)
	- Output 2 is for outgoing responses to queries. In the current script, packets are discarded because there's no other router in the subnets. There is a simulation of querier election possible but we'll discuss that later.

There are also some files that will create and parse packets, these can be found in GroupQueryGenerator.xx and GroupRecordGenerator.xx.



This section will describe how to use everything.

You can either manually put everything together (putting the source files in elements/local/ in click), or you can use our shell script.
There are 3 scripts you'll have to place next to the click-<version> directory: run.sh, runAndCompileScript.sh and install.sh.

install.sh: the commands for building click (make -j2 and ./configure....)

runAndCompileScript.sh: Used for compiling click after you added extra elements. You'll have to give the name of the script you want to run as well. The script you pass as an argument is expected to be in the directory "scripts" which is also next to the sh file itself.
For example you can do: sh runAndCompileScript.sh ipnetwork.click
This will compile click and run scripts/ipnetwork.click.

run.sh: the same as runAndCompileScript.sh but without the compiling

The directory structure looks as follows:

within scripts: your script
within click: ofcourse your click with in /elements/local our elements



To simulate querier election:
There's a handler for a RouterInterface which simulates a query being received.
	write router/interfacex.TakeOverQuery
	write router/interfacex.PassiveQuery
where the x is either a 1 or a 2 (in the current script).
The first one is when simulating that the router lost a query (and schedules a response accordingly) where the second one doesn't affect the router at all. To schedule this response, the state of all router interfaces is needed, that's where the RouterInterfaceConnector comes into play. Its name is self explanatory.
When a router won or lost an election, it is printed in the terminal (because waiting for the query suppression to be over would take a long time). We know this doesn't prove it works, but it proves we understand the protocol.













