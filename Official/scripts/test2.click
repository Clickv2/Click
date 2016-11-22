AddressInfo(sourceAddr 10.0.0.1 1A:7C:3E:90:78:41);
AddressInfo(responderAddr 10.0.0.2 1A:7C:3E:90:78:42);
AddressInfo(multAddr 224.0.0.22);

source::GroupReportGeneratorElement(SRC sourceAddr, DST multAddr);
responder::ICMPPingResponder;
switch::ListenEtherSwitch;


elementclass Router { $src | 
	
	querier::ARPQuerier($src);
	responder::ARPResponder($src);
	arpclass::Classifier(12/0806 20/0001, 12/0806 20/0002, -); // queries, responses, data
	
	input [0]
		-> ToDump(dumps/input.dump)
		-> [0]querier;

	querier
		-> ToDump(dumps/querier.dump)
		-> [0]output;

	input [1]
		-> arpclass;
		
	arpclass[0] // queries
		-> responder
		-> [0]output; // to network
  	
	arpclass[1] // replies
		-> [1]querier;
	
	arpclass[2] // data
		-> filter::HostEtherFilter($src);
		
	filter[0]
		-> Strip(14)
		-> MarkIPHeader
		-> [1] output

	filter[1]
		-> Discard;
}



source
	-> IPEncap(2, sourceAddr, 224.0.0.22)
	-> CheckIPHeader
	//-> EtherEncap(0x0800, sourceAddr, responderAddr)
	-> ToDump(dumps/test.dump)
	-> Print("yas")
	-> [0] sourceRouter::Router(sourceAddr) [0]
	-> [0] switch

switch[0]
	-> [1] sourceRouter [1]
	-> Discard

responder
	-> [0] responderRouter::Router(responderAddr) [0]
	-> [1] switch	
	
switch[1]
	-> [1] responderRouter [1]
	-> responder

switch[2]
	-> Discard

