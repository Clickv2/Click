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
For the router it's a tiny bit different (a router can act like a client as well)
write router/routerInterface.Join x.x.x.x

In the router, you'll see a ServerInterface element. The name is incorrect, but it was far too late to change that. Future updates will adjust this name.
It has one input and three outputs.
	- Output 0 is to send IGMP queries
	- Output 1 is to forward the IGMP packets (not messages)
	- Output 2 is for packets that are given on the input, but that are not used by IGMP, or that are incorrect

There are also some files that will create and parse packets, these can be found in GroupQueryGenerator.xx and GroupRecordGenerator.xx.
IGMPFilter.xx is currently not used but might be useful in the future. It filters packets that are IGMP packets from those that aren't.



This section will describe how to use everything.

You can either manually put everything together (putting the source files in elements/local/ in click), or you can use our shell script.
There are 3 scripts you'll have to place next to the click-<version> directory: run.sh, runAndCompileScript.sh and install.sh.

install.sh: the commands for building click (make -j2 and ./configure....)

runAndCompileScript.sh: Used for compiling click after you added extra elements. You'll have to give the name of the script you want to run as well. The script you pass as an argument is expected to be in the directory "scripts" which is also next to the sh file itself.
For example you can do: sh runAndCompileScript.sh ipnetwork.click
This will compile click and run scripts/ipnetwork.click.

run.sh: the same as runAndCompileScript.sh but without the compiling

The directory structure looks as follows:
click-<version>    scripts    runAndCompileScript.sh	install.sh    run.sh	dumps

within scripts: your script
within click: ofcourse your click with in /elements/local your elements

Now we have provided the scripts map, in the scripts you'll see ToDump elements commented out. If you want to make use of this, uncomment them and make a "dumps" directory (see directory structure above). This is just to show you what our elements produce. The name of the dump files are obvious.














