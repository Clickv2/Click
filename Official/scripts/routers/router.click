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
		-> Print("Sending to arp")
		-> ToDump(dumps/what.dump, ENCAP IP)
		-> client2_arpq;

	rt[4]
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
		-> Print("Packet received on interface 0")
		-> toClients::Tee

	toClients[0]
		-> Print("Packet received on interface 1")
		//-> IPEncap(17, $client1_address, 224.0.0.55)
		-> ToDump(dumps/wutwut.dump, ENCAP IP)
		-> interface1::ServerInterface(MRP 123, SFLAG false, QRV 5, QQIC 10)

	toClients[1]
		//-> IPEncap(17, $client2_address, 224.0.0.55)
		-> interface2::ServerInterface(MRP 123, SFLAG false, QRV 5, QQIC 10)

	paintSwitch [2]
		-> interface1
		-> IPEncap(2, $server_address, $client1_address)
		// TODO change sender address!!!
		-> ToDump(dumps/toI1IP, ENCAP IP)
		// TODO Send to dude
		-> client1_paint

	interface1 [1]
		//-> ToDump(dumps/o2.dump)
		-> client1_paint

	interface1 [2]
		//-> ToDump(dumps/o3.dump)
		-> Discard

	paintSwitch [3]
		-> interface2
		-> IPEncap(2, $server_address, $client1_address)
		// TODO change sender address!!!
		-> ToDump(dumps/toI2IP, ENCAP IP)
		// TODO Send to dude
		-> client2_paint

	interface2 [1]
		//-> ToDump(dumps/o2.dump)
		-> client2_paint

	interface2 [2]
		//-> ToDump(dumps/o3.dump)
		-> Discard

	paintSwitch [0]
		-> Print("Shouldn't get here")
		-> ToDump(dumps/error.dump)
		-> Discard
}

