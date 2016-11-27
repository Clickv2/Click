// Output configuration: 
//
// Packets for the network are put on output 0
// Packets for the host are put on output 1

elementclass Client {
	$address, $gateway |

	ip :: Strip(14)
		-> CheckIPHeader()
		-> rt :: StaticIPLookup(
					$address:ip/32 0,
					$address:ipnet 0,
					224.0.0.0/4 2,
					0.0.0.0/0.0.0.0 $gateway 1)
		-> [1]output;
	
	rt[1]
		//-> ToDump(dumps/broadcast.dump, ENCAP IP)
		-> DropBroadcasts
		-> ttl :: DecIPTTL
		-> ipgw :: IPGWOptions($address)
		-> FixIPSrc($address)
		-> frag :: IPFragmenter(1500)
		-> arpq :: ARPQuerier($address)
		-> output;

	ipgw[1]
		-> ICMPError($address, parameterproblem)
		-> output;
	
	ttl[1]
		-> ICMPError($address, timeexceeded)
		-> output; 

	frag[1]
		-> ICMPError($address, unreachable, needfrag)
		-> output;

	// Incoming Packets
	input
		//-> ToDump(dumps/testsuccess.dump)
		-> HostEtherFilter($address)
		-> in_cl :: Classifier(12/0806 20/0001, 12/0806 20/0002, 12/0800)
		-> arp_res :: ARPResponder($address)
		-> output;

	in_cl[1]
		-> [1]arpq;
	
	in_cl[2]
		//-> ToDump(dumps/IPSTUFF.dump)
		-> ip;

	rt[2]
		// Lorin interface hier en merge me de (tijdelijke) interface hieronder
		-> ToDump(dumps/receivedByClientInterface.dump, ENCAP IP)
		-> interface::InterfaceElement(ADDRESS $address)
		//-> ToDump(dumps/forme.dump, ENCAP IP)
		-> [1]output

	interface[1]
		-> IPEncap(2, $address, 224.0.0.22, TTL 1)
		-> ToDump(dumps/msg.dump, ENCAP IP)
		-> MarkIPHeader
		-> CheckIPHeader
		-> ipgw

	interface[2]
		-> ToDump(dumps/bad.dump, ENCAP IP)
		-> Discard
}
