#include <click/config.h>
#include <click/confparse.hh>
#include <click/error.hh>
#include "ServerInterface.hh"
#include "GroupRecordGenerator.hh"
#include "GroupQueryGenerator.hh"
#include <clicknet/ip.h>
#include <clicknet/ether.h>
#include <click/timer.hh>

#include <time.h>
#include <stdlib.h>

CLICK_DECLS

ServerInterface::ServerInterface() {}

ServerInterface::~ServerInterface() {}

int ServerInterface::configure(Vector<String> &conf, ErrorHandler *errh) {
	if (cp_va_kparse(conf, this, errh,
			"MRP", cpkM, cpInteger, &f_maximumMaxRespCode,
			"SFLAG", cpkM, cpBool, &f_SFlag,
			"QRV", cpkM, cpInteger, &f_QRV,
			"QQIC", cpkM, cpInteger, &f_QQIC,
			 cpEnd) < 0)
		return -1;
	return 0;
}
void ServerInterface::push(int port, Packet* p){

	/// make the check for igmp as an element
	//click_chatter("packet received on interface\n");
	click_ip *ipHeader = (click_ip *)p->data();
	int protocol = ipHeader->ip_p;
	IPAddress dst = ipHeader->ip_dst;
	IPAddress routerListen = IPAddress("224.0.0.22");

	if (protocol == IP_PROTO_IGMP and dst == routerListen){
		//click_chatter("RECEIVED IGMP REPORT\n");
		this->interpretGroupReport(p);
		return;
	}
	bool forwardMulticast = false;
	for (int i = 0; i < f_state.size(); i++){
		//click_chatter("Comparing: ");
		//click_chatter("With: ");
		//click_chatter(dst.unparse().c_str());
		if (dst == f_state.at(i).f_ip){
			//click_chatter("send packet!!!!!!!!!!");
			forwardMulticast = true;
			break;
		}
	}

	if (forwardMulticast){
		//click_chatter("RECEIVED IGMP PACKET\n");
		output(1).push(p);
		return;
	}
	//click_chatter("RECEIVED IP?\n");
	/// Last option, regular IP
	//output(2).push(p);
}

void ServerInterface::interpretGroupReport(Packet* p){
	GroupReportParser parser;
	parser.parsePacket(p);

	Vector<struct GroupRecordStatic> records = parser.getGroupRecords();
	/// TODO: anything with the source and destination?
	//IPAddress getSRC() const;
	//IPAddress getDST() const;


	Vector<IPAddress> toListen;
	Vector<IPAddress> toQuery;

	for (int i = 0; i < records.size(); i++){
		struct GroupRecordStatic currentRecord = records.at(i);
		if (!SUPPRESS_OUTPUT && currentRecord.nrOfSources != 0){
			click_chatter("NrOfSources in report is non-empty.\n");
		}
		uint8_t filterMode = currentRecord.recordType;
		IPAddress mcaddr = IPAddress(currentRecord.multicastAddress);

		if (filterMode == CHANGE_TO_INCLUDE){
			/// send query to verify interest
			bool alreadyInList = false;
			for (int i = 0; i < toQuery.size(); i++){
				if (toQuery.at(i) == mcaddr){
					alreadyInList = true;
					break;
				}
			}

			if (! alreadyInList){
				toQuery.push_back(mcaddr);
			}
			continue;
		}
		if (filterMode == CHANGE_TO_EXCLUDE){
			//click_chatter("CHANGE TO EX");
			bool alreadyInList = false;
			for (int i = 0; i < toListen.size(); i++){
				if (toListen.at(i) == mcaddr){
					alreadyInList = true;
					break;
				}
			}

			if (! alreadyInList){
				toListen.push_back(mcaddr);
			}
			continue;
		}
		if (filterMode == MODE_IS_INCLUDE){
			continue;
		}
		if (filterMode == MODE_IS_EXCLUDE){
			/// TODO refresh timer later
			bool alreadyInList = false;
			for (int i = 0; i < toListen.size(); i++){
				if (toListen.at(i) == mcaddr){
					alreadyInList = true;
					break;
				}
			}

			if (! alreadyInList){
				toListen.push_back(mcaddr);
			}
			continue;
		}
	}
	this->updateInterface(toListen, toQuery);
}

void ServerInterface::sendSpecificQuery(IPAddress multicastAddress){
	GroupQueryGenerator generator;
	IPAddress dst = IPAddress("224.0.0.1");
	Packet* p = generator.makeNewPacket(f_maximumMaxRespCode, f_SFlag, f_QRV, f_QQIC, multicastAddress);
	output(0).push(p);
	/// TODO can i remove p?
}


void ServerInterface::updateInterface(Vector<IPAddress>& toListen, Vector<IPAddress>& toQuery){
	for (int j = 0; j < toListen.size(); j++){
		bool alreadyInList = false;
		for (int i = 0; i < f_state.size(); i++){
			if (toListen.at(j) == toListen.at(i)){
				alreadyInList = true;
				break;
			}
		}

		if (! alreadyInList){
			click_chatter("Now listening to ");
			click_chatter(toListen.at(j).unparse().c_str());
			/// TODO remove hardcoded timeout
			RouterRecord rec = RouterRecord(toListen.at(j), MODE_IS_EXCLUDE, 5000, this);
			f_state.push_back(rec);
		}
	}

	/*for (int i = 0; i < toQuery.size(); i++){
		GroupQueryGenerator generator;
		Packet* p = generator.makeNewPacket(f_maximumMaxRespCode, f_SFlag,f_QRV, f_QQIC, toQuery.at(i));
		output(0).push(p);
	}*/
	for (int i = 0; i < toQuery.size(); i++){
		for (int j = 0; j < f_state.size(); j++){
			if (toQuery.at(i) == f_state.at(j).f_ip){
				click_chatter("query");
				click_chatter(f_state.at(j).f_ip.unparse().c_str());
				//f_toForward.erase(f_toForward.begin() + j);
				GroupQueryGenerator gen;
				Packet* p = gen.makeNewPacket(f_maximumMaxRespCode, f_SFlag, f_QRV, f_QQIC, f_state.at(j).f_ip);
				output(0).push(p);
				break;
			}
		}
	}
}


RouterRecord::RouterRecord(IPAddress ip, uint8_t filterMode, unsigned int timeOut, Element* parentInterface){
	f_ip = ip;
	f_filterMode = filterMode;
	f_timeOut = timeOut;
	f_timerExpired = false;
	f_parentInterface = parentInterface;

	f_groupTimer = new Timer(run_timer, this);
	f_groupTimer->initialize(parentInterface);
	f_groupTimer->schedule_after_msec(f_timeOut);
}

RouterRecord::~RouterRecord(){/*TODO delete timer*/}

void RouterRecord::runTimer(){
	f_timerExpired = true;
	click_chatter("timer expired");
}

void RouterRecord::refreshInterest(){
	f_groupTimer->unschedule();
	f_groupTimer->schedule_after_msec(f_timeOut);
	f_timerExpired = false;
	f_filterMode = MODE_IS_EXCLUDE;
}


void run_timer(Timer* timer, void* routerRecord){
	RouterRecord* record = (RouterRecord*) routerRecord;
	record->runTimer();
}


CLICK_ENDDECLS
EXPORT_ELEMENT(ServerInterface)