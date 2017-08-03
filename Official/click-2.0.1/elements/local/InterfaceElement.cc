#include <click/config.h>
#include <click/confparse.hh>
#include <click/error.hh>
#include "GroupRecordGenerator.hh"
#include "GroupQueryGenerator.hh"
#include <clicknet/ip.h>
#include <clicknet/ether.h>
#include <click/timer.hh>
#include "InterfaceElement.hh"

#include <math.h>
#include <time.h>
#include <stdlib.h>
#include <string>
#include <bitset>


CLICK_DECLS

//////////////////////////////////////////////////
// Mechanism to schedule/manage reports         //
//////////////////////////////////////////////////

scheduledStateChangeReportData::scheduledStateChangeReportData(unsigned int _amount, unsigned int _interval, in_addr _multicastAddress, unsigned int _filterMode, Element* _parentInterface, bool immediateSend) {
	amount = _amount;
	sent = 0;

	interval = _interval;
	parentInterface = _parentInterface;

	if (amount > 0) {
		multicastAddresses.push_back(_multicastAddress);
		filterModes.push_back(_filterMode);
		this->sendPacket(!immediateSend);
	}
}

void scheduledStateChangeReportData::addReport(unsigned int _amount, unsigned int _interval, in_addr _multicastAddress, unsigned int _filterMode) {
	unsigned int remainingTime = UINT_MAX;
	unsigned int newRemainingTime = 0;

	if (multicastAddresses.size() != 0) {
		// Reports are scheduled, check the timer
		remainingTime = reportTimer->expiry_steady().msecval() - Timestamp::now_steady().msecval();
		reportTimer->unschedule();
	}

	// TODO not hardcoded
	newRemainingTime = 10000;

	newRemainingTime = (remainingTime > newRemainingTime) ? newRemainingTime:remainingTime;

	// Set the data
	amount = _amount;
	sent = 1;

	interval = _interval;

	bool foundAddress = false;

	for (unsigned int i = 0; i < multicastAddresses.size(); ++i) {
		if (multicastAddresses[i] == _multicastAddress) {
			foundAddress = true;
			filterModes[i] = _filterMode;

			break;
		}
	}

	if (! foundAddress && amount > 1) {
		multicastAddresses.push_back(_multicastAddress);
		filterModes.push_back(_filterMode);
	}

	// Build and send one package immediately
	if (amount > 0) {
		GroupReportGenerator reportgenerator;
		reportgenerator.makeNewPacket(REPORTMESSAGE);

		for (int i = 0; i < multicastAddresses.size(); ++i) {
			reportgenerator.addGroupRecord(filterModes[i], 0, multicastAddresses[i], Vector<struct in_addr>());
		}

		Packet* reportpacket = reportgenerator.getCurrentPacket();
		parentInterface->output(1).push(reportpacket);
	}

	if (amount > 1) {
		// Schedule the next packet with the new remaining time
		reportTimer = new Timer(run_stateChangeReportData_timer, this);
		reportTimer->initialize(parentInterface);
		reportTimer->schedule_after_msec(newRemainingTime);
		click_chatter("scheduled respons after %u", newRemainingTime);
	}
}

void scheduledStateChangeReportData::sendPacket(bool scheduleOnly) {
	if (!scheduleOnly) {
		GroupReportGenerator reportgenerator;
		reportgenerator.makeNewPacket(REPORTMESSAGE);

		for (int i = 0; i < multicastAddresses.size(); ++i) {
			reportgenerator.addGroupRecord(filterModes[i], 0, multicastAddresses[i], Vector<struct in_addr>());
		}

		Packet* reportpacket = reportgenerator.getCurrentPacket();
		parentInterface->output(1).push(reportpacket);

		sent += 1;
	}

	if (sent < amount) {
		// Schedule retransmission
		reportTimer = new Timer(run_stateChangeReportData_timer, this);
		reportTimer->initialize(parentInterface);
		// TODO not hardcoded
		reportTimer->schedule_after_msec(interval);
	} else {
		// All retransmissions are done
		filterModes.clear();
		multicastAddresses.clear();
	}
}

QueryReportScheduler::QueryReportScheduler(unsigned int _interval, Element* _parentInterface) {
	parentInterface = _parentInterface;
	interval = _interval;
}

void QueryReportScheduler::addReport(unsigned int _interval, String _multicastAddress) {
	unsigned int index = 0;
	bool foundAddress = false;

	for (unsigned int i = 0; i < multicastAddresses.size(); ++i) {
		if (_multicastAddress == multicastAddresses[i]) {
			foundAddress = true;
			index = i;
			break;
		}
	}

	if (!foundAddress) {
		// Common case, the address isn't there, just schedule a response
		// TODO not hardcoded
		unsigned int responseTime = 1000;

		multicastAddresses.push_back(_multicastAddress);

		Timer* reportTimer = new Timer(run_queryResponse_timer, new QueryReportData(this, multicastAddresses.back()));
		reportTimer->initialize(parentInterface);
		reportTimer->schedule_after_msec(responseTime);

		click_chatter("SCHEDULED QUERY RESPONSE");

		reportTimers.push_back(reportTimer);
	} else {
		// TODO reschedule if necessary?
	}
}

void run_queryResponse_timer(Timer* timer, void* reportData){
	QueryReportData* data = (QueryReportData*) reportData;
	InterfaceElement* parentInterface = (InterfaceElement*) data->scheduler->parentInterface;

	uint8_t filterMode = MODE_IS_INCLUDE;

	if (data->multicastAddress != "GENERALQUERY") {
		// TODO above string
		// Search specific mc_addr in the interface
		for (unsigned int i = 0; i < parentInterface->state.size(); ++i) {
			interface_record* record = parentInterface->state[i];
			if (IPAddress(record->multicastAddress).unparse() == data->multicastAddress) {
				if (record->FilterMode == filter_mode::EXCLUDE) {
					filterMode = MODE_IS_EXCLUDE;
					click_chatter("MODE IS JOIN");
				}

				break;
			}
		}

		GroupReportGenerator reportgenerator;
		reportgenerator.makeNewPacket(REPORTMESSAGE);

		reportgenerator.addGroupRecord(filterMode, 0, IPAddress(data->multicastAddress).in_addr(), Vector<struct in_addr>());

		Packet* reportpacket = reportgenerator.getCurrentPacket();
		parentInterface->output(1).push(reportpacket);
		click_chatter("SENDING");
	} else {
		// TODO Respond to general query
	}

	// Remove data from scheduler
	QueryReportScheduler* scheduler = data->scheduler;
	unsigned int index = 0;
	bool found = false;

	for (unsigned int i = 0; i < scheduler->multicastAddresses.size(); ++i) {
		if (data->multicastAddress == scheduler->multicastAddresses[i]) {
			index = i;
			found = true;
			break;
		}
	}

	if (found) {
		scheduler->multicastAddresses.erase(scheduler->multicastAddresses.begin() + index);
		delete scheduler->reportTimers[index];
		scheduler->reportTimers.erase(scheduler->reportTimers.begin() + index);
	}

	delete data;
}

void run_stateChangeReportData_timer(Timer* timer, void* reportData){
	scheduledStateChangeReportData* data = (scheduledStateChangeReportData*) reportData;

	data->sendPacket();
}

int _encoder(int to_encode) {
	if (to_encode < 128) { return to_encode; }
	else {
		for (int i = 3;i <= 10; i++) {
			int exp = 1 << i;
			if (to_encode/exp <= 31 && to_encode/exp >= 16) {
				int mantissa = (to_encode/exp)-16;
				//found mantissa -> Encoding
				int code = 0;
				code = code | 128;
				int counter = 0;
				for (int j = 4; j <= 6; j++) {//encoding exp
					int checker = 1 << counter;
					if ((i-3) & checker) {
						int codexp = 1 << j;
						code = code | codexp;
						//click_chatter("Code exp for %d ms\n", code);
					}
					counter ++;
				}
				counter = 0;
				for (int j = 0; j <=3;j++) {//encoding mantissa

					int checker = 1 << counter;
					if (mantissa & checker) {
						int codmant = 1 <<j;
						code = code | codmant;
						//click_chatter("Code mant for %d ms\n", code);
					}
					counter ++;
					
				}
				//click_chatter("Code exp %d ms\n", i);
				//click_chatter("Code Test %d ms\n", code);
				return code;
				
			}
		}
	}
}

int _decoder(int resp_or_interval) {
	int maxRespTime = 0;
	if (resp_or_interval < 128) {maxRespTime = resp_or_interval;}
	else { //write client31/interface.Join 230.0.0.1
		
		int exponent = 0;
		int mantissa = 0;
		for (int i = 0; i <=3; i++) {
			int checker = 1 << i;
			if (checker & resp_or_interval) {
				mantissa = mantissa | 1 << i ; 
			}
		}
		for (int i = 0; i <= 2; i++) {
			int checker = 1 << i+4;
			if (checker & resp_or_interval) {
				exponent = exponent | 1 << i ; 
			}
		}
		maxRespTime = (mantissa | 16) * ( 1 << exponent+3);
	}
	return maxRespTime;
}

interface_record::interface_record(struct in_addr multicastAddress, filter_mode FilterMode, Vector<struct in_addr> *sourcelist) {
	this->multicastAddress = multicastAddress;
	this->FilterMode= FilterMode;
	this->sourcelist = sourcelist;

}

InterfaceElement::InterfaceElement(): stateChangeReports(0, 0, IPAddress(""), 0, this), generalQueryReports(0, this){
	this->robustness_Var = 2;
	this->Query_response_interval = 100;
	this->unsolicited_response_interval = 1000;
}

InterfaceElement::~InterfaceElement() {}

void InterfaceElement::pushReply(Packet *p, int outputport) {
	//click_chatter("pushing reply");
	output(outputport).push(p);
	//this->replies_to_send -= 1;

}


void InterfaceElement::push(int port, Packet* p) {
	click_ip *ipHeader = (click_ip *)p->data();
	IPAddress f_dst = ipHeader->ip_dst;
	IPAddress groupaddress;
	bool acceptpacket = false;
	bool acceptquery = false;
	interface_record* currentrecord;

	for (int i = 0; i < this->state.size();i++) {
		IPAddress comp = IPAddress(this->state[i]->multicastAddress);
		if (f_dst == this->state[i]->multicastAddress && this->state[i]->FilterMode == EXCLUDE) {
			// accept if UDP packet
			acceptpacket = true;
			groupaddress = this->state[i]->multicastAddress;
			currentrecord = this->state[i];
		} else if (f_dst == this->state[i]->multicastAddress) {
			// accept if query
			acceptquery = true;
			groupaddress = this->state[i]->multicastAddress;
			currentrecord = this->state[i];
		}
	}

	if (f_dst == IPAddress("224.0.0.1") || acceptpacket == true || acceptquery == true) {
		GroupQueryParser parser;
		parser.parsePacket(p);

		// Get and set variables from the packet
		int maxRespCode = parser.getMaxRespCode();
		IPAddress SRC = parser.getSRC();
		IPAddress DST = parser.getDST();
		IPAddress receivedGroupAddress = parser.getGroupAddress();
		bool SFlag = parser.getSFlag();
		int QRV = parser.getQRV();
		int QQIC = parser.getQQIC();
		this->robustness_Var = QRV;
		if (this->robustness_Var == 0) {this->robustness_Var = 2;}
		int maxRespTime;
		int Query_Interval;
		bool udppacket = false;

		maxRespTime = _decoder(maxRespCode);
		Query_Interval = _decoder(QQIC);

		if (receivedGroupAddress == IPAddress("")) {
			// TODO
			// General query received
			
		}
		else if (receivedGroupAddress == groupaddress) {
			// TODO
			// Group specific query
			click_chatter("QUERY");
			generalQueryReports.addReport(1000, receivedGroupAddress.unparse());
		} else {
			// udp packet
			udppacket = true;
			if (currentrecord->FilterMode == EXCLUDE && acceptpacket)
				output(0).push(p);
		}

	}

	p->kill();
}

int InterfaceElement::configure(Vector<String> & conf, ErrorHandler *errh) {
	IPAddress interfaceAddress;
	if (cp_va_kparse(conf, this, errh, cpEnd) < 0) {
		return -1;
	}
	return 0;
}


int InterfaceElement::Leave(const String &conf, Element *e, void* thunk, ErrorHandler *errh) {
	GroupReportGenerator reportgenerator;
	InterfaceElement *me = (InterfaceElement* ) e;
	struct in_addr multicastAddressin;
	if (cp_va_kparse(conf, e, errh,
				 "MULTICAST-ADDR", cpkP, cpIPAddress, &multicastAddressin,
				  cpEnd) < 0) {
		return -1;
	}

	bool sendLeave = false;
	int index_to_remove;
	for (int i =0;i < me->state.size();i++) {
		if (me->state[i]->multicastAddress == multicastAddressin) {
			if (me->state[i]->FilterMode != INCLUDE) {
				sendLeave = true;
			}

			me->state[i]->FilterMode = INCLUDE;
			me->state[i]->sourcelist->clear();
			index_to_remove = i;

		}
	}
	if (sendLeave) {
		// Note that this part is reached when the state actually changed!
		if (me->robustness_Var >= 8) {me->robustness_Var = 2;}
		me->stateChangeReports.addReport(me->robustness_Var, me->unsolicited_response_interval, multicastAddressin, CHANGE_TO_INCLUDE);
	}

	me->state.erase(me->state.begin() + index_to_remove);
}


int InterfaceElement::Join(const String &conf, Element *e, void* thunk, ErrorHandler *errh) {
	GroupReportGenerator reportgenerator;
	InterfaceElement *me = (InterfaceElement* ) e;
	struct in_addr multicastAddressin;
	if (cp_va_kparse(conf, me, errh,
					 "MULTICAST-ADDR", cpkP, cpIPAddress, &multicastAddressin,
					  cpEnd) < 0) {

		return -1;
	}

	bool present = false;
	bool sendJoin = false;

	for (int i = 0;i < me->state.size();i++) {
		if (me->state[i]->multicastAddress == multicastAddressin) {
			if (me->state[i]->FilterMode != EXCLUDE) {
				// Send a join report
				sendJoin = true;
			}
			
			me->state[i]->FilterMode = EXCLUDE;
			me->state[i]->sourcelist->clear();
			present = true;
		}
	}

	if (not present) {
		// TODO remove ptrs?

		Vector<struct in_addr> *sourcelist = new Vector<struct in_addr>();
		interface_record *newInterfacerec = new interface_record(multicastAddressin, EXCLUDE, sourcelist);
		me->state.push_back(newInterfacerec);
		sendJoin = true;
	}

	if (sendJoin) {
		// Note that this part is reached when the state actually changed!
		if (me->robustness_Var >= 8) {me->robustness_Var = 2;}
		me->stateChangeReports.addReport(me->robustness_Var, me->unsolicited_response_interval, multicastAddressin, CHANGE_TO_EXCLUDE);
	}
}

int InterfaceElement::QuietLeave(const String &conf, Element *e, void* thunk, ErrorHandler *errh) {
	GroupReportGenerator reportgenerator;
	InterfaceElement *me = (InterfaceElement* ) e;
	struct in_addr multicastAddressin;
	if (cp_va_kparse(conf, e, errh,
				 "MULTICAST-ADDR", cpkP, cpIPAddress, &multicastAddressin,
				  cpEnd) < 0) {
		return -1;
	}
	
	bool changed = false;
	int index_to_remove;
	for (int i =0;i < me->state.size();i++) {
		if (me->state[i]->multicastAddress == multicastAddressin) {
			if (me->state[i]->FilterMode != INCLUDE) {
				changed = true;
			}
			me->state[i]->FilterMode = INCLUDE;
			me->state[i]->sourcelist->clear();
			index_to_remove = i;

		}
	}
	me->state.erase(me->state.begin() + index_to_remove);
}

void InterfaceElement::add_handlers() {
	add_write_handler("Join", &Join, (void*)0);
	add_write_handler("Leave", &Leave, (void*)0);
	add_write_handler("QuietLeave", &QuietLeave, (void*)0);
}


CLICK_ENDDECLS
EXPORT_ELEMENT(InterfaceElement)
