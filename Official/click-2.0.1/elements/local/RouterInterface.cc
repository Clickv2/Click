#include <click/config.h>
#include <click/confparse.hh>
#include <click/error.hh>
#include "RouterInterface.hh"
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

RouterInterface::RouterInterface() {
}

RouterInterface::~RouterInterface() {}

int RouterInterface::configure(Vector<String> &conf, ErrorHandler *errh) {
	f_makeOutput = false;

	++f_nextID;
	f_myID = f_nextID;

	int MRC = 0;
	int QRV = 0;
	int QQIC = 0;
	int QI = 0;
	int QRI = 0;
	if (cp_va_kparse(conf, this, errh,
			"MRC", cpkM, cpInteger, &MRC,
			"SFLAG", cpkM, cpBool, &f_SFlag,
			"QRV", cpkM, cpInteger, &QRV,
			"QQIC", cpkM, cpInteger, &QQIC,
			"IP", cpkM, cpIPAddress, &f_myIP,
			"QUERY_INTERVAL", cpkM, cpInteger, &QI,
			"QUERY_RESPONSE_INTERVAL", cpkM, cpInteger, &QRI,
			"CONNECTOR", cpkM, cpElementCast, "RouterInterfaceConnector", &f_interfaceConnector,
			 cpEnd) < 0)
		return -1;

	f_queryInterval = QI * 1000;
	f_queryResponseInterval = QRI * 100;
	f_maximumMaxRespCode = MRC;
	f_QRV = QRV;
	f_QQIC = QQIC;
	if (QRV > 7 || QRV < 0) {
		errh->error("QRV must be between 0 and 7.");
		return -1;
	}
	if (MRC < 0 || MRC > 255) {
		errh->error("MRC must be between 0 and 255.");
		return -1;
	}
	if (QQIC < 0 || QQIC > 255) {
		errh->error("QQIC must be between 0 and 255.");
		return -1;
	}
	if (QI <= 0) {
		errh->error("QUERY_INTERVAL must be strictly positive");
		return -1;
	}
	if (QRI <= 0) {
		errh->error("QUERY_RESPONSE_INTERVAL must be strictly positive");
		return -1;
	}

	f_queryInterval = 125000;
	f_queryResponseInterval = 10000;
	f_lastMemberQueryInterval = _decoder(f_maximumMaxRespCode) * 100;

	f_interfaceConnector->logonElement(this);

	f_groupMembershipInterval = f_QRV * f_queryInterval + f_queryResponseInterval;

	f_lastMemberQueryCount = f_QRV;
	f_lastMemberQueryTime = f_lastMemberQueryCount * f_lastMemberQueryInterval;

	f_otherQuerierPresentInterval = f_QRV * f_queryInterval + f_queryResponseInterval / 2.0;
	f_startupQueryInterval = f_queryInterval / 4.0;
	f_startupQueryCount = f_QRV;

	f_schedulers.push_back(
		new PacketScheduler("", f_queryInterval, this, -1, 0));


	//click_chatter("MRC: %d", f_maximumMaxRespCode);
	//click_chatter("MRT: %d", f_lastMemberQueryInterval);
	//click_chatter("SFLAG: %d", f_SFlag);
	//click_chatter("QRV: %d", f_QRV);
	//click_chatter("QQIC: %d", f_QQIC);
	//click_chatter("IP: %d", f_myIP);
	//click_chatter("f_queryInterval: %d", f_queryInterval);
	//click_chatter("f_queryResponseInterval: %u", f_queryResponseInterval);
	//click_chatter("f_groupMembershipInterval: %f", f_groupMembershipInterval);
	//click_chatter("f_lastMemberQueryTime: %d", f_lastMemberQueryTime);
	//click_chatter("f_otherQuerierPresentInterval: %f", f_otherQuerierPresentInterval);
	//click_chatter("f_startupQueryInterval: %f", f_startupQueryInterval);
	//click_chatter("f_startupQueryCount: %f", f_startupQueryCount);

	return 0;
}

void RouterInterface::deleteRecord(RouterRecord* record) {
	for(int i = 0; i < f_state.size(); i++) {
		if (f_state.at(i) == *record) {
			f_state.erase(f_state.begin() + i);
			return;
		}
	}
}

void RouterInterface::deleteScheduler(PacketScheduler* scheduler) {
	bool removed = true;

	while(removed && f_schedulers.size() > 0) {
		removed = false;
		for (int i = 0; i < f_schedulers.size(); i++) {
			if (f_schedulers.at(i)->f_multicastAddr == scheduler->f_multicastAddr) {
				f_schedulers.erase(f_schedulers.begin() + i);
				removed = true;

				// TODO
				//delete scheduler;
				break;
			}
		}
	}
}

void RouterInterface::push(int port, Packet* p) {
	click_ip *ipHeader = (click_ip *)p->data();
	int protocol = ipHeader->ip_p;
	IPAddress dst = ipHeader->ip_dst;
	IPAddress routerListen = IPAddress("224.0.0.22");
	IPAddress generalQuery = IPAddress("224.0.0.1");

	if (protocol == IP_PROTO_IGMP and dst == routerListen) {
		this->interpretGroupReport(p);
		p->kill();
		return;
	}

	if (protocol == IP_PROTO_IGMP and dst == generalQuery) {
		// #MAGA
		this->querierElection(p);
		p->kill();
		return;
	}

	bool forwardMulticast = false;
	for (int i = 0; i < f_state.size(); i++) {
		if (dst == f_state.at(i).f_ip) {
			forwardMulticast = true;
			break;
		}
	}

	if (forwardMulticast) {
		output(1).push(p);
		return;
	}
	p->kill();
}

void RouterInterface::querierElection(Packet* p) {
	click_ip *ipHeader = (click_ip *)p->data();
	int protocol = ipHeader->ip_p;
	IPAddress src = ipHeader->ip_src;
	if (ntohl(f_myIP) > ntohl(src)) {
		click_chatter("Lost election");
		for (int i = 0; i < f_schedulers.size(); i++) {
			if (f_schedulers.at(i)->f_multicastAddr == "") {
				/// Empty string means general query!!!
				f_schedulers.at(i)->suppress(f_otherQuerierPresentInterval, f_startupQueryInterval, f_startupQueryCount);

				GroupQueryParser parser;
				parser.parsePacket(p);
				f_QRV = parser.getQRV();
				int maxRespTime = _decoder(parser.getMaxRespCode()) * 100;

				f_schedulers.push_back(new PacketScheduler(f_interfaceConnector->getQueryResponse(),
					maxRespTime, this, 1, 3));
				return;
			}
		}
	} else {
		click_chatter("won election");
	}
}

void RouterInterface::interpretGroupReport(Packet* p) {
	GroupReportParser parser;
	parser.parsePacket(p);

	Vector<struct GroupRecordStatic> records = parser.getGroupRecords();

	Vector<IPAddress> toListen;
	Vector<IPAddress> toQuery;
	for (int i = 0; i < records.size(); i++) {
		struct GroupRecordStatic currentRecord = records.at(i);
		if (!SUPPRESS_OUTPUT && currentRecord.nrOfSources != 0) {
			//click_chatter("NrOfSources in report is non-empty.\n");
		}
		uint8_t filterMode = currentRecord.recordType;
		IPAddress mcaddr = IPAddress(currentRecord.multicastAddress);

		if (filterMode == CHANGE_TO_INCLUDE) {
			bool alreadyInList = false;
			for (int i = 0; i < toQuery.size(); i++) {
				if (toQuery.at(i) == mcaddr) {
					alreadyInList = true;
					break;
				}
			}

			if (! alreadyInList) {
				toQuery.push_back(mcaddr);
			}
			continue;
		}
		if (filterMode == CHANGE_TO_EXCLUDE) {
			bool alreadyInList = false;
			for (int i = 0; i < toListen.size(); i++) {
				if (toListen.at(i) == mcaddr) {
					alreadyInList = true;
					break;
				}
			}

			if (! alreadyInList) {
				toListen.push_back(mcaddr);
			}
			continue;
		}
		if (filterMode == MODE_IS_INCLUDE) {
			continue;
		}
		if (filterMode == MODE_IS_EXCLUDE) {
			bool alreadyInList = false;
			for (int i = 0; i < toListen.size(); i++) {
				if (toListen.at(i) == mcaddr) {
					alreadyInList = true;
					break;
				}
			}

			if (! alreadyInList) {
				toListen.push_back(mcaddr);
			}
			continue;
		}
	}
	this->updateInterface(toListen, toQuery);
}

void RouterInterface::sendSpecificQuery(IPAddress multicastAddress) {
	/// if S-flag is clear (false) => update group timer
	GroupQueryGenerator generator;
	IPAddress dst = IPAddress("224.0.0.1");
	Packet* p = generator.makeNewPacket(f_lastMemberQueryInterval, f_SFlag, f_QRV, f_QQIC, multicastAddress,
		f_myIP, multicastAddress);

	bool found = false;
	for (int i = 0; i < f_schedulers.size(); i++) {
		if (f_schedulers.at(i)->f_multicastAddr == multicastAddress.unparse().c_str()) {

			f_schedulers.at(i)->merge(f_lastMemberQueryInterval, f_lastMemberQueryCount);
			found = true;
			break;
		}
	}

	if (! found) {
		f_schedulers.push_back(new PacketScheduler(multicastAddress.unparse().c_str(),
			f_lastMemberQueryInterval, this, f_lastMemberQueryCount, 0));
	}


	for (int i = 0; i < f_state.size(); i++) {
		if (f_state.at(i).f_ip == multicastAddress) {
			f_state.at(i).f_groupTimer->unschedule();
			f_state.at(i).f_groupTimer->schedule_after_msec(f_lastMemberQueryTime);
			break;
		}
	}

	// TODO push or don't push?
	// output(0).push(p);
}


void RouterInterface::updateInterface(Vector<IPAddress>& toListen, Vector<IPAddress>& toQuery) {
	for (int j = 0; j < toListen.size(); j++) {
		bool alreadyInList = false;
		for (int i = 0; i < f_state.size(); i++) {
			if (toListen.at(j) == f_state.at(i).f_ip) {
				/// This is when you start goofing around with handlers to set the variables
				/// Suppress flag = not set (false) => update timers
				if (! f_SFlag) {
					f_state.at(i).f_timeOut = f_groupMembershipInterval;
					f_state.at(i).refreshInterest();
				}
				alreadyInList = true;
				break;
			}
		}

		if (! alreadyInList) {
			RouterRecord rec = RouterRecord(toListen.at(j), MODE_IS_EXCLUDE, f_groupMembershipInterval, this);
			f_state.push_back(rec);
		}
	}

	for (int i = 0; i < toQuery.size(); i++) {
		for (int j = 0; j < f_state.size(); j++) {
			if (toQuery.at(i) == f_state.at(j).f_ip) {
				this->sendSpecificQuery(f_state.at(j).f_ip);
				break;
			}
		}
	}
}

void RouterInterface::add_handlers() {
	add_write_handler("TakeOverQuery", &TakeOverQuery, (void*)0);
	add_write_handler("PassiveQuery", &PassiveQuery, (void*)0);
	add_write_handler("Verbose", &Verbose, (void*)0);
	add_write_handler("Silent", &Silent, (void*)0);
}

int RouterInterface::PassiveQuery(const String &conf, Element *e, void* thunk, ErrorHandler *errh) {
	RouterInterface *me = (RouterInterface* ) e;
	if (cp_va_kparse(conf, me, errh, cpEnd) < 0) {
	    return -1;
	}

	GroupQueryGenerator gen;
	Packet* p = gen.makeNewPacket(80, false, 2, me->f_QQIC, IPAddress(""), IPAddress("255.255.255.255"), IPAddress("224.0.0.1"));
	me->push(0, p);

	return 0;
}

int RouterInterface::TakeOverQuery(const String &conf, Element *e, void* thunk, ErrorHandler *errh) {
	RouterInterface *me = (RouterInterface* ) e;
	if (cp_va_kparse(conf, me, errh, cpEnd) < 0) {
	    return -1;
	}

	GroupQueryGenerator gen;
	Packet* p = gen.makeNewPacket(80, false, 6, me->f_QQIC, IPAddress(""), IPAddress("1.1.1.1"), IPAddress("224.0.0.1"));
	me->push(0,p);

	return 0;
}

int RouterInterface::Verbose(const String &conf, Element *e, void* thunk, ErrorHandler *errh) {
	GroupReportGenerator reportgenerator;
	RouterInterface *me = (RouterInterface* ) e;
	struct in_addr multicastAddressin;
	if (cp_va_kparse(conf, e, errh, cpEnd) < 0) {
		return -1;
	}
	
	me->f_makeOutput = true;
}

int RouterInterface::Silent(const String &conf, Element *e, void* thunk, ErrorHandler *errh) {
	GroupReportGenerator reportgenerator;
	RouterInterface *me = (RouterInterface* ) e;
	struct in_addr multicastAddressin;
	if (cp_va_kparse(conf, e, errh, cpEnd) < 0) {
		return -1;
	}
	
	me->f_makeOutput = false;
}













RouterRecord::RouterRecord(IPAddress ip, uint8_t filterMode, double timeOut, Element* parentInterface) {
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

RouterRecord::~RouterRecord() {
	if (f_groupTimer != NULL) {
		/// TODO
		// delete f_groupTimer;
	}
}

void RouterRecord::refreshInterest() {
	f_groupTimer->unschedule();
	f_groupTimer->schedule_after_msec(f_timeOut);
	f_filterMode = MODE_IS_EXCLUDE;
}

bool RouterRecord::operator==(RouterRecord& otherRecord) {

	if (this->f_parentInterface == otherRecord.f_parentInterface
		&& this->f_ip == otherRecord.f_ip && this->f_filterMode == otherRecord.f_filterMode
		&& this->f_timeOut == otherRecord.f_timeOut) {

		return true;
	}
	return false;
}


void run_timer(Timer* timer, void* routerRecord) {
	RouterRecord* record = (RouterRecord*) routerRecord;
	RouterInterface* interface = (RouterInterface*) record->f_parentInterface;
	interface->deleteRecord(record);
	
	// TODO
	//delete record;
}












PacketScheduler::PacketScheduler(String multicastAddr, int sendEvery_X_ms, Element* parentInterface,
		int amountOfTimes, unsigned int outputPort) {

	f_suppress = false;

	f_multicastAddr = multicastAddr;
	f_time = sendEvery_X_ms;
	f_parentInterface = (RouterInterface*) parentInterface;
	f_amountOfTimes = amountOfTimes;
	f_amountOfTimesSent = 0;
	f_outputPort = outputPort;
	f_ID = f_nextID;
	f_nextID++;

	f_timer = new Timer(sendToSchedulerPacket, this);
	f_timer->initialize(f_parentInterface);

	if (multicastAddr != "" && f_parentInterface->f_makeOutput) {
		click_chatter("Sending group specific query (%s) from router interface with ID %i in %ums\n", f_multicastAddr.c_str(), f_parentInterface->f_myID, f_time);
	} else if (f_parentInterface->f_makeOutput) {
		click_chatter("Sending general query from router interface with ID %i in %ums\n", f_parentInterface->f_myID, f_time);
	}

	f_timer->schedule_after_msec(f_time);

	f_startupInterval = -1.0;
	f_startupCount = -1;
	f_suppressTimer = NULL;
	f_startupSent = -1;
}

PacketScheduler::PacketScheduler(GroupReportGenerator gen, int sendEvery_X_ms, Element* parentInterface, int amountOfTimes, unsigned int outputPort) {

	f_suppress = false;

	f_multicastAddr = "-1";
	f_time = sendEvery_X_ms;
	f_parentInterface = (RouterInterface*) parentInterface;
	f_amountOfTimes = amountOfTimes;
	f_amountOfTimesSent = 0;
	f_outputPort = outputPort;
	f_ID = f_nextID;
	f_nextID++;

	f_gen = gen;

	f_timer = new Timer(sendToSchedulerPacket, this);
	f_timer->initialize(f_parentInterface);
	f_timer->schedule_after_msec(f_time);

	f_startupInterval = -1.0;
	f_startupCount = -1;
	f_suppressTimer = NULL;
	f_startupSent = -1;
}

void PacketScheduler::suppress(double time, double startupInterval, unsigned int startupCount) {
	f_timer->clear();

	f_suppress = true;
	f_startupInterval = startupInterval;
	f_startupCount = startupCount;
	f_startupSent = 0;

	if (f_suppressTimer != NULL) {
		/// TODO
		delete f_suppressTimer;
		f_suppressTimer = NULL;
	}

	f_suppressTimer = new Timer(startup, this);
	f_suppressTimer->initialize(f_parentInterface);
	f_suppressTimer->schedule_after_msec(time);
	f_timer->clear();
}

void PacketScheduler::reset() {
	f_timer->unschedule();
	f_timer->schedule_after_msec(f_time);
	f_amountOfTimesSent = 0;
}

void PacketScheduler::merge(int sendEvery_X_ms, int amountOfTimes) {
	f_amountOfTimesSent = 0;
	f_amountOfTimes = amountOfTimes;
	f_time = sendEvery_X_ms;

	unsigned int remainingTime = f_timer->expiry_steady().msecval() - Timestamp::now_steady().msecval();
	unsigned int newRemainingTime = f_time < remainingTime ? f_time : remainingTime;

	if (f_parentInterface->f_makeOutput) {
		click_chatter("Merging scheduled queries on router interface with ID %i, given choice between %ims and %ims, next query will be sent after %ims\n",
				f_parentInterface->f_myID, f_time, remainingTime, newRemainingTime);
	}

	f_timer->unschedule();
	f_timer->schedule_after_msec(newRemainingTime);
}

void PacketScheduler::sendPacket() {
	if (f_multicastAddr != "-1") {
		GroupQueryGenerator generator;

		String dst = "";
		if (f_multicastAddr != "") {
			dst = f_multicastAddr;

			if (f_parentInterface->f_makeOutput) {
				click_chatter("Sending group specific query (%s) from router interface with ID %i\n", f_multicastAddr.c_str(), f_parentInterface->f_myID);
			}
		} else {
			dst = "224.0.0.1";

			if (f_parentInterface->f_makeOutput) {
				click_chatter("Sending general query from router interface with ID %i\n", f_parentInterface->f_myID);
			}
		}

		Packet* p = generator.makeNewPacket(f_parentInterface->f_maximumMaxRespCode, f_parentInterface->f_SFlag,
			f_parentInterface->f_QRV, f_parentInterface->f_QQIC, IPAddress(f_multicastAddr), f_parentInterface->f_myIP, IPAddress(dst));

		f_parentInterface->output(f_outputPort).push(p);

		f_amountOfTimesSent++;
	} else {
		f_parentInterface->output(f_outputPort).push(f_gen.getCurrentPacket());
		f_amountOfTimesSent++;
	}
}

void sendToSchedulerPacket(Timer* timer, void* scheduler) {
	PacketScheduler* myScheduler = (PacketScheduler*) scheduler;

	if (myScheduler->f_amountOfTimes > myScheduler->f_amountOfTimesSent || myScheduler->f_amountOfTimes == -1) {
		myScheduler->sendPacket();
		myScheduler->f_timer->schedule_after_msec(myScheduler->f_time);
		if (myScheduler->f_multicastAddr != "") {
			if (myScheduler->f_parentInterface->f_makeOutput) {
				click_chatter("Scheduling group specific query (%s) from router interface with ID %i in %ums\n",
						myScheduler->f_multicastAddr.c_str(),
						myScheduler->f_parentInterface->f_myID,
						myScheduler->f_time);
			}
		} else if (myScheduler->f_parentInterface->f_makeOutput) {
			click_chatter("Sending general query from router interface with ID %i in %ums\n",
					myScheduler->f_parentInterface->f_myID,
					myScheduler->f_time);
		}
	} else {
		myScheduler->f_parentInterface->deleteScheduler(myScheduler);
		if (myScheduler->f_multicastAddr != "" && myScheduler->f_parentInterface->f_makeOutput) {
			click_chatter("Stopped sending group specific queries (%s) from router interface with ID %i\n", myScheduler->f_multicastAddr.c_str(), myScheduler->f_parentInterface->f_myID);
		} else if (myScheduler->f_parentInterface->f_makeOutput) {
			click_chatter("Stopped sending general query from router interface with ID %i\n", myScheduler->f_parentInterface->f_myID);
		}
	}
}

void startup(Timer* timer, void* scheduler) {
	PacketScheduler* myScheduler = (PacketScheduler*) scheduler;

	if (myScheduler->f_startupSent < myScheduler->f_startupCount) {
		// TODO output
		myScheduler->sendPacket();
		myScheduler->f_suppressTimer->schedule_after_msec(myScheduler->f_startupInterval / 10);
		myScheduler->f_amountOfTimesSent--;
		myScheduler->f_startupSent++;
	} else {

		myScheduler->f_suppress = false;
		myScheduler->f_timer->schedule_after_msec(myScheduler->f_time);


		// TODO
		
		//delete myScheduler->f_suppressTimer;
		myScheduler->f_suppressTimer = NULL;
		myScheduler->f_startupSent = 0;
	}
}

unsigned int PacketScheduler::f_nextID = 0;
int RouterInterface::f_nextID = 0;

CLICK_ENDDECLS
EXPORT_ELEMENT(RouterInterface)
