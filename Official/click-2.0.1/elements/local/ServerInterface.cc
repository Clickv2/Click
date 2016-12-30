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
#include <iostream>
#include "InterfaceElement.hh"

#include <iostream>
using namespace std;

CLICK_DECLS

ServerInterface::ServerInterface() {
}

ServerInterface::~ServerInterface() {}

int ServerInterface::configure(Vector<String> &conf, ErrorHandler *errh) {
	
	if (cp_va_kparse(conf, this, errh,
			"MRC", cpkM, cpInteger, &f_maximumMaxRespCode,
			"SFLAG", cpkM, cpBool, &f_SFlag,
			"QRV", cpkM, cpInteger, &f_QRV,
			"QQIC", cpkM, cpInteger, &f_QQIC,
			"IP", cpkM, cpIPAddress, &f_myIP,
			"CONNECTOR", cpkM, cpElementCast, "RouterInterfaceConnector", &f_interfaceConnector,
			 cpEnd) < 0)
		return -1;

	f_queryInterval = 125000;
	f_queryResponseInterval = 10000;
	f_lastMemberQueryInterval = _decoder(f_maximumMaxRespCode) * 100;
	click_chatter("MRT%d", f_lastMemberQueryInterval);

	f_interfaceConnector->logonElement(this);

	f_groupMembershipInterval = f_QRV * f_queryInterval + f_queryResponseInterval;

	f_lastMemberQueryCount = f_QRV;
	f_lastMemberQueryTime = f_lastMemberQueryCount * f_lastMemberQueryInterval;

	f_otherQuerierPresentInterval = f_QRV * f_queryInterval + f_queryResponseInterval / 2.0;
	f_startupQueryInterval = f_queryInterval / 4.0;
	f_startupQueryCount = f_QRV;

	f_schedulers.push_back(
		new PacketScheduler("", f_queryInterval, this, -1, 0));

	return 0;
}

void ServerInterface::deleteRecord(RouterRecord* record){
	for(int i = 0; i < f_state.size(); i++){
		if (f_state.at(i) == *record){
			click_chatter("\n\n\nDELETED RECORD\n\n\n");
			f_state.erase(f_state.begin() + i);
			return;
		}
	}
}

void ServerInterface::deleteScheduler(PacketScheduler* scheduler){
	/// TODO delete by ID or by address of source
	bool removed = true;

	while(removed && f_schedulers.size() > 0){
		removed = false;
		for (int i = 0; i < f_schedulers.size(); i++){
			if (f_schedulers.at(i)->f_multicastAddr == scheduler->f_multicastAddr){
				/// TODO free mem of scheduler
				f_schedulers.erase(f_schedulers.begin() + i);
				removed = true;
				click_chatter("\n\n\nDELETE SCHEDULER\n\n\n");
				break;
			}
		}
	}
}

void ServerInterface::push(int port, Packet* p){
	click_ip *ipHeader = (click_ip *)p->data();
	int protocol = ipHeader->ip_p;
	IPAddress dst = ipHeader->ip_dst;
	IPAddress routerListen = IPAddress("224.0.0.22");
	IPAddress generalQuery = IPAddress("224.0.0.1");

	if (protocol == IP_PROTO_IGMP and dst == routerListen){
		this->interpretGroupReport(p);
		p->kill();
		return;
	}

	if (protocol == IP_PROTO_IGMP and dst == generalQuery){
		// #MAGA
		this->querierElection(p);
		p->kill();
		return;
	}

	bool forwardMulticast = false;
	for (int i = 0; i < f_state.size(); i++){
		if (dst == f_state.at(i).f_ip){
			click_chatter("Sending packet from router (if the client already left, wait for the timeout (60s))");
			click_chatter("You can wait for the general queries to be sent to see them in action (~125s if i remember correctly).\n");
			forwardMulticast = true;
			break;
		}
	}

	if (forwardMulticast){
		output(1).push(p);
		return;
	}
	p->kill();
}

void ServerInterface::querierElection(Packet* p){
	click_ip *ipHeader = (click_ip *)p->data();
	int protocol = ipHeader->ip_p;
	IPAddress src = ipHeader->ip_src;
	if (ntohl(ntohl(f_myIP) > ntohl(src))){
		for (int i = 0; i < f_schedulers.size(); i++){
			if (f_schedulers.at(i)->f_multicastAddr == ""){
				/// Empty string means general query!!!
				f_schedulers.at(i)->suppress(f_otherQuerierPresentInterval, f_startupQueryInterval, f_startupQueryCount);

				GroupQueryParser parser;
				parser.parsePacket(p);
				f_QRV = parser.getQRV();
				int maxRespTime = _decoder(parser.getMaxRespCode()) * 100;
				click_chatter("NEW QRV: %d, MRT: %d, MRC: %d", f_QRV, maxRespTime, parser.getMaxRespCode());



				f_schedulers.push_back(new PacketScheduler(f_interfaceConnector->getQueryResponse(),
					maxRespTime, this, 1, 3));
				return;
			}
		}
	}
}

void ServerInterface::interpretGroupReport(Packet* p){
	GroupReportParser parser;
	parser.parsePacket(p);

	Vector<struct GroupRecordStatic> records = parser.getGroupRecords();

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
	/// if S-flag is clear (false) => update group timer
	GroupQueryGenerator generator;
	IPAddress dst = IPAddress("224.0.0.1");
	Packet* p = generator.makeNewPacket(f_lastMemberQueryInterval, f_SFlag, f_QRV, f_QQIC, multicastAddress,
		f_myIP, multicastAddress);

	/// TODO Schedule LMQC - 1 retransmission sent every LMQI over LMQT
	/// TODO pick rnd LMQI

	bool found = false;
	for (int i = 0; i < f_schedulers.size(); i++){
		if (f_schedulers.at(i)->f_multicastAddr == multicastAddress.unparse().c_str()){
			return;
			f_schedulers.at(i)->reset();
			found = true;
			break;
		}
	}

	if(! found){
		f_schedulers.push_back(new PacketScheduler(multicastAddress.unparse().c_str(),
			f_lastMemberQueryInterval, this, f_lastMemberQueryCount - 1, 0));
	}


	for (int i = 0; i < f_state.size(); i++){
		if (f_state.at(i).f_ip == multicastAddress){
			f_state.at(i).f_groupTimer->unschedule();
			f_state.at(i).f_groupTimer->schedule_after_msec(f_lastMemberQueryTime);
			break;
		}
	}
	/// TODO this is impossible but it is in the RFC: if the group timer is larger than the LMQT then S-flag is set
	output(0).push(p);
}


void ServerInterface::updateInterface(Vector<IPAddress>& toListen, Vector<IPAddress>& toQuery){
	for (int j = 0; j < toListen.size(); j++){
		bool alreadyInList = false;
		for (int i = 0; i < f_state.size(); i++){
			if (toListen.at(j) == f_state.at(i).f_ip){
				/// This is when you start goofing around with handlers to set the variables
				/// Suppress flag = not set (false) => update timers
				if (! f_SFlag){
					f_state.at(i).f_timeOut = f_groupMembershipInterval;
					f_state.at(i).refreshInterest();
				}
				alreadyInList = true;
				break;
			}
		}

		if (! alreadyInList){
			RouterRecord rec = RouterRecord(toListen.at(j), MODE_IS_EXCLUDE, f_groupMembershipInterval, this);
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
				this->sendSpecificQuery(f_state.at(j).f_ip);
				break;
			}
		}
	}
}

void ServerInterface::add_handlers(){
	add_write_handler("TakeOverQuery", &TakeOverQuery, (void*)0);
	add_write_handler("PassiveQuery", &TakeOverQuery, (void*)0);
}

int ServerInterface::PassiveQuery(const String &conf, Element *e, void* thunk, ErrorHandler *errh){
	ServerInterface *me = (ServerInterface* ) e;
	if(cp_va_kparse(conf, me, errh, cpEnd) < 0){
	    return -1;
	}

	GroupQueryGenerator gen;
	Packet* p = gen.makeNewPacket(80, false, 2, me->f_QQIC, IPAddress(""), IPAddress("255.255.255.255"), IPAddress("224.0.0.1"));
	me->push(0, p);

	return 0;
}

int ServerInterface::TakeOverQuery(const String &conf, Element *e, void* thunk, ErrorHandler *errh){
	ServerInterface *me = (ServerInterface* ) e;
	if(cp_va_kparse(conf, me, errh, cpEnd) < 0){
	    return -1;
	}

	GroupQueryGenerator gen;
	Packet* p = gen.makeNewPacket(80, false, 6, me->f_QQIC, IPAddress(""), IPAddress("1.1.1.1"), IPAddress("224.0.0.1"));
	me->push(0,p);

	return 0;
}













RouterRecord::RouterRecord(IPAddress ip, uint8_t filterMode, double timeOut, Element* parentInterface){
	f_ip = ip;
	f_filterMode = filterMode;
	f_timeOut = timeOut;
	f_parentInterface = parentInterface;

	/// Because vectors and pointers aren't friends
	RouterRecord* newRecord = new RouterRecord(*this);

	f_groupTimer = new Timer(run_timer, newRecord);
	f_groupTimer->initialize(f_parentInterface);
	f_groupTimer->schedule_after_msec(f_timeOut);
}

RouterRecord::~RouterRecord(){/*TODO delete timer*/}

void RouterRecord::refreshInterest(){
	click_chatter("\n\nREFRESH INTEREST\n\n");
	f_groupTimer->unschedule();
	f_groupTimer->schedule_after_msec(f_timeOut);
	f_filterMode = MODE_IS_EXCLUDE;
}

bool RouterRecord::operator==(RouterRecord& otherRecord){

	if (this->f_parentInterface == otherRecord.f_parentInterface
		&& this->f_ip == otherRecord.f_ip && this->f_filterMode == otherRecord.f_filterMode
		&& this->f_timeOut == otherRecord.f_timeOut){

		return true;
	}
	return false;
}


void run_timer(Timer* timer, void* routerRecord){
	RouterRecord* record = (RouterRecord*) routerRecord;
	ServerInterface* interface = (ServerInterface*) record->f_parentInterface;
	interface->deleteRecord(record);
	click_chatter("\n\n\nDELETING RECORD (delay is normal because this uses timeouts)\n\n\n");

	delete record;
}












PacketScheduler::PacketScheduler(String multicastAddr, int sendEvery_X_ms, Element* parentInterface,
		int amountOfTimes, unsigned int outputPort){

	f_suppress = false;

	f_multicastAddr = multicastAddr;
	f_time = sendEvery_X_ms;
	f_parentInterface = (ServerInterface*) parentInterface;
	f_amountOfTimes = amountOfTimes;
	f_amountOfTimesSent = 0;
	f_outputPort = outputPort;
	f_ID = f_nextID;
	f_nextID++;
	
	//click_chatter("made scheduler with %d times every %d ms", f_amountOfTimes, f_time);

	f_timer = new Timer(sendToSchedulerPacket, this);
	f_timer->initialize(f_parentInterface);
	f_timer->schedule_after_msec(f_time);

	f_startupInterval = -1.0;
	f_startupCount = -1;
	f_suppressTimer = NULL;
	f_startupSent = -1;
}

PacketScheduler::PacketScheduler(GroupReportGenerator gen, int sendEvery_X_ms, Element* parentInterface, int amountOfTimes, unsigned int outputPort){

	f_suppress = false;

	f_multicastAddr = "-1";
	f_time = sendEvery_X_ms;
	f_parentInterface = (ServerInterface*) parentInterface;
	f_amountOfTimes = amountOfTimes;
	f_amountOfTimesSent = 0;
	f_outputPort = outputPort;
	f_ID = f_nextID;
	f_nextID++;

	f_gen = gen;
	
	//click_chatter("made scheduler with %d times every %d ms", f_amountOfTimes, f_time);

	f_timer = new Timer(sendToSchedulerPacket, this);
	f_timer->initialize(f_parentInterface);
	f_timer->schedule_after_msec(f_time);

	f_startupInterval = -1.0;
	f_startupCount = -1;
	f_suppressTimer = NULL;
	f_startupSent = -1;
}

PacketScheduler::~PacketScheduler(){
	/// Can't delete packets... its private
	///delete f_packet;
	// if (f_packet != NULL){
	// 	f_packet->kill();
	// }
	click_chatter("Removing scheduler");
}

void PacketScheduler::suppress(double time, double startupInterval, unsigned int startupCount){
	//click_chatter("suppressing %f ms", time);
	f_timer->clear();

/// TODO RERMOVA
	time /= 100;

	click_chatter("suppressed %f ms", time);
	f_suppress = true;
	f_startupInterval = startupInterval;
	f_startupCount = startupCount;
	f_startupSent = 0;

	if (f_suppressTimer != NULL){
		/// TODO delete timer
		f_suppressTimer = NULL;
	}

	f_suppressTimer = new Timer(startup, this);
	f_suppressTimer->initialize(f_parentInterface);
	f_suppressTimer->schedule_after_msec(time);
	f_timer->clear();
}

void PacketScheduler::reset(){
	//click_chatter("MERGE SCHEDULERS");

	f_timer->unschedule();
	f_timer->schedule_after_msec(f_time);
	f_amountOfTimesSent = 0;
}

void PacketScheduler::sendPacket(){
	// click_chatter("Sending scheduled query to ");
	// click_chatter(f_multicastAddr.c_str());
	// click_chatter("\n");
	if (f_multicastAddr.c_str() == ""){
		click_chatter("\nSending General query\n");
	}else{
		click_chatter("\nSending scheduled query to ");
		click_chatter(f_multicastAddr.c_str());
		click_chatter("\n");
	}
	if (f_multicastAddr != "-1"){
		GroupQueryGenerator generator;

		String dst = "";
		if (f_multicastAddr != ""){
			dst = f_multicastAddr;
		}else{
			dst = "224.0.0.1";
		}

		Packet* p = generator.makeNewPacket(f_parentInterface->f_maximumMaxRespCode, f_parentInterface->f_SFlag,
			f_parentInterface->f_QRV, f_parentInterface->f_QQIC, IPAddress(f_multicastAddr), f_parentInterface->f_myIP, IPAddress(dst));

		f_parentInterface->output(f_outputPort).push(p);

		f_amountOfTimesSent++;
	}else{
		click_chatter("ok");
		click_chatter("kek");
		f_parentInterface->output(f_outputPort).push(f_gen.getCurrentPacket());
		click_chatter("okk");
		f_amountOfTimesSent++;
	}
}

void sendToSchedulerPacket(Timer* timer, void* scheduler){
	PacketScheduler* myScheduler = (PacketScheduler*) scheduler;

	if (myScheduler->f_amountOfTimes > myScheduler->f_amountOfTimesSent || myScheduler->f_amountOfTimes == -1){
		myScheduler->sendPacket();
		myScheduler->f_timer->schedule_after_msec(myScheduler->f_time);
	}else{
		myScheduler->f_parentInterface->deleteScheduler(myScheduler);
	}
}

void startup(Timer* timer, void* scheduler){
	click_chatter("back in town");
	PacketScheduler* myScheduler = (PacketScheduler*) scheduler;

	//click_chatter("Sent %d out of %d pkg", myScheduler->f_startupSent, myScheduler->f_startupCount);
	if (myScheduler->f_startupSent < myScheduler->f_startupCount){
		//click_chatter("sending startup pkg");
		myScheduler->sendPacket();
		myScheduler->f_suppressTimer->schedule_after_msec(myScheduler->f_startupInterval / 10);
		myScheduler->f_amountOfTimesSent--;
		myScheduler->f_startupSent++;
	}else{

		myScheduler->f_suppress = false;
		myScheduler->f_timer->schedule_after_msec(myScheduler->f_time);


		/// TODO delete timer
		myScheduler->f_suppressTimer = NULL;
		myScheduler->f_startupSent = 0;
	}
}

unsigned int PacketScheduler::f_nextID = 0;

CLICK_ENDDECLS
EXPORT_ELEMENT(ServerInterface)