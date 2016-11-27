Made By Lorin Teugels and Sam Mylle
University of Antwerp



This section will describe the elements we made and how they are used.

In the client compound element, you'll see the InterfaceElement.
It has one input and 3 outputs:
	- output 0 if the input packet is IGMP and the interface listens to that multicast address
	- output 1 if the state of the interface has changed or if a report is requested by receiving a query
You'll be able to join or leave a certain multicast address by calling a handler as follows:
write clientxx/interface.Join x.x.x.x
Where the current multicast address is set to 230.0.0.1s

In the router, you'll see a ServerInterface element. The name is incorrect, but it was far too late to change that. Future updates will adjust this name.
It has one input and three outputs.
	- Output 0 is to send IGMP queries
	- Output 1 is to forward the IGMP packets (not messages)
	- Output 2 is for packets that are given on the input, but that are not used by IGMP, or that are incorrect

There are also some files that will create and parse packets, these can be found in GroupQueryGenerator.xx and GroupRecordGenerator.xx.
IGMPFilter.xx is currently not used but might be useful in the future. It filters packets that are IGMP packets from those that aren't.



This section will describe how to use everything.

You can either manually put everything together
