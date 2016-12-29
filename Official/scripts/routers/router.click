// Router with three interfaces
// The input/output configuration is as follows:
//
// Input:
//	[0]: packets received on the 192.168.1.0/24 network
//	[1]: packets received on the 192.168.2.0/24 network
//	[2]: packets received on the 192.168.3.0/24 network
//
// Output:
//	[0]: packets sent to the 192.168.1.0/24 network
//	[1]: packets sent to the 192.168.2.0/24 network
//	[2]: packets sent to the 192.168.3.0/24 network
//  [3]: packets destined for the router itself

elementclass Router {
	$server_address, $client1_address, $client2_address |

	// Shared IP input path and routing table
	ip :: Strip(14)
		-> CheckIPHeader
		-> rt :: StaticIPLookup(
					$server_address:ip/32 0,
					$client1_address:ip/32 0,
					$client2_address:ip/32 0,
					$server_address:ipnet 1,
					$client1_address:ipnet 2,
					$client2_address:ipnet 3,
					224.0.0.0/4 4);
	
	// ARP responses are copied to each ARPQuerier and the host.
	arpt :: Tee (3);
	
	// Input and output paths for interface 0
	input
		-> HostEtherFilter($server_address)
		-> server_class :: Classifier(12/0806 20/0001, 12/0806 20/0002, -)
		-> ARPResponder($server_address)
		-> output;

	server_arpq :: ARPQuerier($server_address)
		-> output;

	server_class[1]
		-> arpt
		-> [1]server_arpq;

	server_class[2]
		-> Paint(1)
		-> ip;

	// Input and output paths for interface 1
	input[1]
		-> HostEtherFilter($client1_address)
		-> client1_class :: Classifier(12/0806 20/0001, 12/0806 20/0002, -)
		-> ARPResponder($client1_address)
		-> [1]output;

	client1_arpq :: ARPQuerier($client1_address)
		-> [1]output;

	client1_class[1]
		-> arpt[1]
		-> [1]client1_arpq;

	client1_class[2]
		-> Paint(2)
		-> ip;

	// Input and output paths for interface 2
	input[2]
		-> HostEtherFilter($client2_address)
		-> client2_class :: Classifier(12/0806 20/0001, 12/0806 20/0002, -)
		-> ARPResponder($client2_address)
		-> [2]output;

	client2_arpq :: ARPQuerier($client2_address)
		-> [2]output;

	client2_class[1]
		-> arpt[2]
		-> [1]client2_arpq;

	client2_class[2]
		-> Paint(3)
		-> ip;
	
	// Local delivery
	rt[0]
		-> [3]output
	
	// Forwarding paths per interface
	rt[1]
		-> DropBroadcasts
		-> server_paint :: PaintTee(1)
		-> server_ipgw :: IPGWOptions($server_address)
		-> FixIPSrc($server_address)
		-> server_ttl :: DecIPTTL
		-> server_frag :: IPFragmenter(1500)
		-> server_arpq;
	
	server_paint[1]
		-> ICMPError($server_address, redirect, host)
		-> rt;

	server_ipgw[1]
		-> ICMPError($server_address, parameterproblem)
		-> rt;

	server_ttl[1]
		-> ICMPError($server_address, timeexceeded)
		-> rt;

	server_frag[1]
		-> ICMPError($server_address, unreachable, needfrag)
		-> rt;
	

	rt[2]
		-> DropBroadcasts
		-> client1_paint :: PaintTee(2)
		-> client1_ipgw :: IPGWOptions($client1_address)
		-> FixIPSrc($client1_address)
		-> client1_ttl :: DecIPTTL
		-> client1_frag :: IPFragmenter(1500)
		-> ToDump(dumps/outgoing.dump, ENCAP IP)
		-> client1_arpq;
	
	client1_paint[1]
		-> ICMPError($client1_address, redirect, host)
		-> rt;

	client1_ipgw[1]
		-> ICMPError($client1_address, parameterproblem)
		-> rt;

	client1_ttl[1]
		-> ICMPError($client1_address, timeexceeded)
		-> rt;

	client1_frag[1]
		-> ICMPError($client1_address, unreachable, needfrag)
		-> rt;


	rt[3]
		-> DropBroadcasts
		-> client2_paint :: PaintTee(2)
		-> client2_ipgw :: IPGWOptions($client2_address)
		-> FixIPSrc($client2_address)
		-> client2_ttl :: DecIPTTL
		-> client2_frag :: IPFragmenter(1500)
		-> client2_arpq;

	rt[4]
		//-> ToDump(dumps/multicastReceivedOnRouter.dump, ENCAP IP)
		-> paintSwitch::PaintSwitch
	
	client2_paint[1]
		-> ICMPError($client2_address, redirect, host)
		-> rt;

	client2_ipgw[1]
		-> ICMPError($client2_address, parameterproblem)
		-> rt;

	client2_ttl[1]
		-> ICMPError($client2_address, timeexceeded)
		-> rt;

	client2_frag[1]
		-> ICMPError($client2_address, unreachable, needfrag)
		-> rt;

	// My stuff

	paintSwitch [1]
		-> toClients::Tee

	toClients[0]
		-> ToDump(dumps/forRouter1.dump, ENCAP IP)
		-> interface1::ServerInterface(MRC 120, SFLAG false, QRV 5, QQIC 10, IP $client1_address)

	toClients[1]
		-> ToDump(dumps/forRouter2.dump, ENCAP IP)
		-> interface2::ServerInterface(MRC 120, SFLAG false, QRV 5, QQIC 10, IP $client2_address)

	toClients[2]
		-> routerInterface::InterfaceElement()
		//-> ToDump(dumps/forRouter.dump, ENCAP IP)
		-> [3]output

	routerInterface[1]
		// Note that this router doesn't have to send reports
		-> Discard

	paintSwitch [2]
		-> interface1
		// TODO: Note that interface output 0 is currently not used
		// In the future, IGMP queries will be sent from here
		// The stuff below was temporary
		// TODO on all interfaces: fix src IP?????
		//-> IPEncap(2, $client1_address, 230.0.0.1)
		// TODO don't forget this in other interfaces
		-> MarkIPHeader
		-> ToDump(dumps/query1.dump, ENCAP IP)
		-> client1_paint
		//-> Discard

	interface1 [1]
		-> ToDump(dumps/udp.dump, ENCAP IP)
		-> client1_paint

	interface1 [2]
		-> Discard

	paintSwitch [3]
		-> interface2
		// TODO: Note that interface output 0 is currently not used
		// In the future, IGMP queries will be sent from here
		// The stuff below was temporary
		//-> IPEncap(2, $client2_address, 230.0.0.1)
		-> ToDump(dumps/query2.dump, ENCAP IP)
		-> client2_paint
		//-> Discard

	interface2 [1]
		-> client2_paint

	interface2 [2]
		-> Discard

	paintSwitch [0]
		-> Discard
}

