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

	void InterfaceElement::run_timer(Timer* timer){
		//click_chatter("Sending reply");
		this->pushReply(this->scheduledReports[0],1);
		//click_chatter("reply sent");
		this->scheduled = false;
		this->scheduledReports.pop_front();
		this->scheduledTypes.pop_front();	

	}

	void run_reportTimer(Timer* timer, void* interfacepr){

		InterfaceElement* interface = static_cast<InterfaceElement*>(interfacepr);
		click_chatter("pops out %d", interface->Reports.size());
		interface->pushReply(interface->Reports[0], 1);
		interface->Reports.pop_front();
		if(interface->Reports.size() > 0){
			interface->report_timer->schedule_after_msec(interface->unsolicited_intervals[0]);
			interface->unsolicited_intervals.pop_front();
		}

	}

	int _encoder(int to_encode){
		if(to_encode < 128){ return to_encode; }
		else{
			for(int i = 3;i <= 10; i++){
				int exp = 1 << i;
				if(to_encode/exp <= 15){
					int mantissa = to_encode/exp;
					//found mantissa -> Encoding
					int code = 0;
					code = code | 128;
					int counter = 0;
					for(int j = 4; j <= 6; j++){//encoding exp
						int checker = 1 << counter;
						if((i-3) & checker){
							int codexp = 1 << j;
							code = code | codexp;
							//click_chatter("Code exp for %d ms\n", code);
						}
						counter ++;
					}
					counter = 0;
					for(int j = 0; j <=3;j++){//encoding mantissa

						int checker = 1 << counter;
						if(mantissa & checker){
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

	int _decoder(int resp_or_interval){
		int maxRespTime = 0;
		if(resp_or_interval < 128){maxRespTime = resp_or_interval;}
		else{ //write client31/interface.Join 230.0.0.1
			
			int exponent = 0;
			int mantissa = 0;
			for(int i = 0; i <=3; i++){
				int checker = 1 << i;
				if(checker & resp_or_interval){
					mantissa = mantissa | 1 << i ; 
				}
			}
			for(int i = 0; i <= 2; i++){
				int checker = 1 << i+4;
				if(checker & resp_or_interval){
					exponent = exponent | 1 << i ; 
				}
			}
			maxRespTime = mantissa * ( 1 << exponent+3);
		}
		return maxRespTime;
	}

    	interface_record::interface_record(struct in_addr multicastAddress, filter_mode FilterMode, Vector<struct in_addr> *sourcelist){
		this->multicastAddress = multicastAddress;
		this->FilterMode= FilterMode;
		this->sourcelist = sourcelist;

	}


	InterfaceElement::InterfaceElement(){
		this->filterchange = false;
		this->robustness_Var = 2;
		this->Query_response_interval = 100;
		InterfaceElement* extrapointertome = this;

		this->reply_timer = new Timer(this);

		this->report_timer = new Timer(run_reportTimer, this);

		this->amount_replies_sent = 0;
		this->countdown = -1;
		this->scheduled = false;
		this->unsolicited_response_interval = 1000;
	}

	InterfaceElement::~InterfaceElement(){

	}

	void InterfaceElement::pushReply(Packet *p, int outputport){
		//click_chatter("pushing reply");
		output(outputport).push(p);
		//this->replies_to_send -= 1;
	
	}


	void InterfaceElement::push(int port, Packet* p){
		click_ip *ipHeader = (click_ip *)p->data();
		IPAddress f_dst = ipHeader->ip_dst;
		IPAddress groupaddress;
		bool acceptpacket = false;
		for(int i = 0; i < this->state.size();i++){
			IPAddress comp = IPAddress(this->state[i]->multicastAddress);
			if (f_dst == this->state[i]->multicastAddress && this->state[i]->FilterMode == EXCLUDE){
				//output(0).push(p);
				acceptpacket = true;
				groupaddress = this->state[i]->multicastAddress;
			}
		}
		if(f_dst == IPAddress("224.0.0.1") || acceptpacket == true){
			//click_chatter("GOT HERE");
			GroupReportGenerator reportgenerator;
			GroupQueryParser parser;
			parser.parsePacket(p);

			int maxRespCode = parser.getMaxRespCode();
			IPAddress SRC = parser.getSRC();
			IPAddress DST = parser.getDST();
			IPAddress groupAddress = parser.getGroupAddress();
			bool SFlag = parser.getSFlag();
			int QRV = parser.getQRV();
			int QQIC = parser.getQQIC();
			this->robustness_Var = QRV;
			if(this->robustness_Var == 0){this->robustness_Var = 2;}
			int maxRespTime;
			int Query_Interval;
			bool udppacket = false;
			
			//int test = _encoder(1024);
			//click_chatter("DECODED ENCODER %d ms\n", _decoder(test));

			maxRespTime = _decoder(maxRespCode);
			Query_Interval = _decoder(QQIC);
			//maxRespTime = 10;

			click_chatter("maxRespTime %d ms\n", maxRespTime);
			//General query
			reportgenerator.makeNewPacket(REPORTMESSAGE);

			String _types;
			if(groupAddress == IPAddress("")){
				//click_chatter("GENERAL");
				_types = "General";
				for(int i = 0; i < this->state.size(); i++){
					if(this->state[i]->FilterMode == INCLUDE){
						reportgenerator.addGroupRecord(MODE_IS_INCLUDE, 0, this->state[i]->multicastAddress, Vector<struct in_addr>());
					}
					else{
						reportgenerator.addGroupRecord(MODE_IS_EXCLUDE, 0, this->state[i]->multicastAddress, Vector<struct in_addr>());
					}
				}
			}
			//group specific query
			else if(groupAddress == groupaddress){
				//click_chatter("GROUP SPECIFIC");
				_types = "Group";
				for(int i = 0; i < this->state.size(); i++){
					if (this->state[i]->multicastAddress == groupAddress){
						if(this->state[i]->FilterMode == INCLUDE){
							reportgenerator.addGroupRecord(MODE_IS_INCLUDE, 0, this->state[i]->multicastAddress, Vector<struct in_addr>());
						}
						else{
							reportgenerator.addGroupRecord(MODE_IS_EXCLUDE, 0, this->state[i]->multicastAddress, Vector<struct in_addr>());
						}
					}
				}
			}
			else{
				//udp packet
				udppacket = true;
				output(0).push(p);
			}
			if(not udppacket){
				Packet* reportpacket = reportgenerator.getCurrentPacket();
				if(this->scheduledReports.size() == 0){
	  				srand (time(NULL));
					this->countdown = rand() % maxRespTime;
					this->scheduledReports.push_back(reportpacket);
					this->scheduledTypes.push_back(_types);
					this->scheduled = true;
					this->reply_timer->initialize(this);
					this->reply_timer->schedule_after_msec(this->countdown);
					//click_chatter("Sending reply after %d ms\n", this->countdown);

				
				}
				else{

	  				srand (time(NULL));
					int _countdown = rand() % maxRespTime;
					this->scheduledTypes.push_back(_types);
					this->PacketMerge(reportpacket, Query_Interval, _countdown);

				}
			}
			//output(1).push(reportpacket);

		}			
		/*if(not pushed){
			output(2).push(p);
		}*/		
		
	}


	int InterfaceElement::PacketMerge(Packet* reportpacket, int QQI, int tempcountdown){

		Timestamp _expirestamp = this->reply_timer->expiry();
		int _expirems = _expirestamp.msec();
		Timestamp _nowstamp = Timestamp::now();
		int _nowms = _nowstamp.msec();
		//click_chatter("Sending reply after %d ms\n", _nowms);
		int timelength = _expirems - _nowms;

		if(this->scheduledTypes[0] == "General"){
			if(timelength < tempcountdown){
				//click_chatter("merge option 1");
				this->scheduledTypes.pop_front();
				return 0;
			}
		}

		if(this->scheduledTypes[1] == "General"){
			//click_chatter("merge option 2");
			this->scheduledReports.push_back(reportpacket);
			this->scheduled = true;
			this->reply_timer->initialize(this);
			this->reply_timer->schedule_after_msec(tempcountdown);
			//click_chatter("Sending reply after %d ms\n", tempcountdown);
			return 0;
		}
		if(this->scheduledTypes[1] == "Group" && this->scheduled == false){ //recheck
			//click_chatter("merge option 3");
			this->scheduledReports.push_back(reportpacket);
			this->scheduled = true;
			this->reply_timer->initialize(this);
			this->reply_timer->schedule_after_msec(tempcountdown);
			//click_chatter("Sending reply after %d ms\n", tempcountdown);
			return 0;
		
		}
		if(this->scheduled == true && (this->scheduledTypes[1] == "Group" /* || empty sourcelist, always true in our case */)){
			//click_chatter("merge option 4");
			this->scheduledReports.push_back(reportpacket);
			this->scheduled = true;
			this->reply_timer->initialize(this);
			int chosen_countdown = tempcountdown;
			if(chosen_countdown > timelength){chosen_countdown = timelength;}
			this->reply_timer->schedule_after_msec(chosen_countdown);
			//click_chatter("Sending reply after %d ms", chosen_countdown);
			//click_chatter(" in stead of after %d ms", tempcountdown);
			//click_chatter( " or %d ms\n", timelength);
			return 0;
		}
	}

	int InterfaceElement::configure(Vector<String> & conf, ErrorHandler *errh){
		IPAddress interfaceAddress;
		if(cp_va_kparse(conf, this, errh, cpEnd) < 0){
			return -1;
		}
		return 0;
	}


	int InterfaceElement::Leave(const String &conf, Element *e, void* thunk, ErrorHandler *errh){
		GroupReportGenerator reportgenerator;
		InterfaceElement *me = (InterfaceElement* ) e;
		struct in_addr multicastAddressin;
        if(cp_va_kparse(conf, e, errh,
					 "MULTICAST-ADDR", cpkP, cpIPAddress, &multicastAddressin,
					 //"SOURCELIST",  0, Vector<cpIPAddress>, sourcelist,
					  cpEnd) < 0){
            return -1;
        }
		//struct interface_record record = {multicastAddressin, FilterMode, sourcelist};
		//interface.append(record)
		
		me->filterchange = true;
		me->change = TO_INCLUDE;
		bool changed = false;
		for(int i =0;i < me->state.size();i++){
			if(me->state[i]->multicastAddress == multicastAddressin){
				if (me->state[i]->FilterMode != INCLUDE){
					changed = true;
				}
				/*else if (me->state[i]->sourcelist.size() != 0){ //sourcelist functionality
					changed = true;
				}*/
				me->state[i]->FilterMode = INCLUDE;
				me->state[i]->sourcelist->clear();

			}
		}
		if (changed){
			reportgenerator.makeNewPacket(REPORTMESSAGE);
			reportgenerator.addGroupRecord(CHANGE_TO_INCLUDE, 0, multicastAddressin, Vector<struct in_addr>());
			Packet* reportpacket = reportgenerator.getCurrentPacket();
			me->output(1).push(reportpacket);
			//CHANGING NOW, REMEMBER SPOT
			int _countdown = 0;
			me->report_timer->initialize(me);
			me->Reports.clear();
			if(me->robustness_Var >= 8){me->robustness_Var = 2;}
			if(me->robustness_Var>=2){
				reportgenerator.makeNewPacket(REPORTMESSAGE);
				reportgenerator.addGroupRecord(CHANGE_TO_EXCLUDE, 0, multicastAddressin, Vector<struct in_addr>());
				Packet* tempreportpacket = reportgenerator.getCurrentPacket();
					me->Reports.push_back(tempreportpacket);
				_countdown = rand() % me->unsolicited_response_interval;
				//click_chatter("amountofcalls %d", _countdown);
				me->report_timer->schedule_after_msec(_countdown);
			}
			for(int i = 0;i < me->robustness_Var-2; i++){
				reportgenerator.makeNewPacket(REPORTMESSAGE);
				reportgenerator.addGroupRecord(CHANGE_TO_EXCLUDE, 0, multicastAddressin, Vector<struct in_addr>());
				Packet* tempreportpacket = reportgenerator.getCurrentPacket();
				me->Reports.push_back(tempreportpacket);
  				srand (time(NULL));
				_countdown = rand() % me->unsolicited_response_interval;
				me->unsolicited_intervals.push_back(_countdown);
				//click_chatter("amountofcalls %d", _countdown);

				/*else{
					click_chatter("rescheduled");
					me->report_timer->reschedule_after_msec(_countdown);
				}*/
			}

		}
	}


	int InterfaceElement::Join(const String &conf, Element *e, void* thunk, ErrorHandler *errh){
		GroupReportGenerator reportgenerator;
		InterfaceElement *me = (InterfaceElement* ) e;
		struct in_addr multicastAddressin;
		if(cp_va_kparse(conf, me, errh,
						 "MULTICAST-ADDR", cpkP, cpIPAddress, &multicastAddressin,
						 //"SOURCELIST",  0, Vector<cpIPAddress>, sourcelist,
						  cpEnd) < 0){

		    return -1;
		}
			//struct interface_record record = {multicastAddressin, FilterMode, sourcelist};
		//interface.append(record)
        // TODO klopt ni?
		me->filterchange = true;
		me->change = TO_EXCLUDE;
		bool present = false;
		bool changed = false;
		for(int i =0;i < me->state.size();i++){
			if(me->state[i]->multicastAddress == multicastAddressin){
				if(me->state[i]->FilterMode != EXCLUDE /*&& me->state[i]->sourcelist.size() == 0*/ ){ //sourcelist functionality
					changed = true;
				}
				
				me->state[i]->FilterMode = EXCLUDE;
				me->state[i]->sourcelist->clear();
				present = true;
			}
		}
		if(not present){
			Vector<struct in_addr> *sourcelist = new Vector<struct in_addr>();
			interface_record *newInterfacerec = new interface_record(multicastAddressin, EXCLUDE, sourcelist);
			me->state.push_back(newInterfacerec);
			changed = true;
		}
		if(changed){
			reportgenerator.makeNewPacket(REPORTMESSAGE);
			reportgenerator.addGroupRecord(CHANGE_TO_EXCLUDE, 0, multicastAddressin, Vector<struct in_addr>());
			Packet* reportpacket = reportgenerator.getCurrentPacket();
			me->output(1).push(reportpacket);

			//CHANGING NOW, REMEMBER SPOT
			me->Reports.clear();
			int _countdown = 0;
			me->report_timer->initialize(me);
			if(me->robustness_Var >= 8){me->robustness_Var = 2;}
			if(me->robustness_Var>=2){
				reportgenerator.makeNewPacket(REPORTMESSAGE);
				reportgenerator.addGroupRecord(CHANGE_TO_EXCLUDE, 0, multicastAddressin, Vector<struct in_addr>());
				Packet* tempreportpacket = reportgenerator.getCurrentPacket();
					me->Reports.push_back(tempreportpacket);
				_countdown = rand() % me->unsolicited_response_interval;
				//click_chatter("amountofcalls %d", _countdown);
				me->report_timer->schedule_after_msec(_countdown);
			}
			for(int i = 0;i < me->robustness_Var-2; i++){
				reportgenerator.makeNewPacket(REPORTMESSAGE);
				reportgenerator.addGroupRecord(CHANGE_TO_EXCLUDE, 0, multicastAddressin, Vector<struct in_addr>());
				Packet* tempreportpacket = reportgenerator.getCurrentPacket();
				me->Reports.push_back(tempreportpacket);
  				srand (time(NULL));
				_countdown = rand() % me->unsolicited_response_interval;
				me->unsolicited_intervals.push_back(_countdown);
				//click_chatter("amountofcalls %d", _countdown);

				/*else{
					click_chatter("rescheduled");
					me->report_timer->reschedule_after_msec(_countdown);
				}*/
			}
		}
    }
	void InterfaceElement::add_handlers(){
		add_write_handler("Join", &Join, (void*)0);
		add_write_handler("Leave", &Leave, (void*)0);
    }

	


CLICK_ENDDECLS
EXPORT_ELEMENT(InterfaceElement)
