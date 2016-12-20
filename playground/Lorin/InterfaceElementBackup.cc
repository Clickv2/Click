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
		click_chatter("Sending reply");
		this->pushReply(this->scheduledReports[0]);
		click_chatter("reply sent");
		this->scheduled = false;
		this->scheduledReports.pop_front();
		

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


		this->amount_replies_sent = 0;
		this->countdown = -1;
		this->scheduled = false;
	}

	InterfaceElement::~InterfaceElement(){

	}

	void InterfaceElement::pushReply(Packet *p){
		click_chatter("pushing reply");
		output(1).push(p);
		//this->replies_to_send -= 1;
	
	}


	void InterfaceElement::push(int port, Packet* p){
		click_ip *ipHeader = (click_ip *)p->data();
		IPAddress f_dst = ipHeader->ip_dst;
		bool acceptpacket = false;
		for(int i = 0; i < this->state.size();i++){
			IPAddress comp = IPAddress(this->state[i]->multicastAddress);
			if (f_dst == this->state[i]->multicastAddress && this->state[i]->FilterMode == EXCLUDE){
				output(0).push(p);
				acceptpacket = true;
			}
		}
		if(f_dst == IPAddress("224.0.0.1") || acceptpacket == true){
			click_chatter("GOT HERE");
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
			int maxRespTime;

			if(maxRespCode < 128){maxRespTime = maxRespCode;}
			else{
				std::string decoder = std::bitset< 8 >( maxRespCode ).to_string();
				int exponent = 3;
				int mantissa = 0;
				for(int i = 1; i <= 3; i++){
					char temp = decoder[i];
					int itemp = temp - '0';
					//exponent += (itemp *2 )**(3-i);
					exponent += pow(itemp*2, 3-i);
				}
				for(int i = 4; i <= 7; i++){
					char temp = decoder[i];
					int itemp = temp - '0';
					//exponent += (itemp *2 )**(3-i);
					mantissa += pow(itemp*2, 7-i);
				}
				maxRespTime = mantissa * pow(2,exponent);
				click_chatter("maxRespTime %d ms\n", maxRespTime);
			}

			//General query
			reportgenerator.makeNewPacket(REPORTMESSAGE);
			if(groupAddress == IPAddress("")){
				click_chatter("GENERAL");
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
			else{
				click_chatter("GROUP SPECIFIC");
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

			Packet* reportpacket = reportgenerator.getCurrentPacket();
			if(this->scheduledReports.size() == 0){
  				srand (time(NULL));
				this->countdown = rand() % maxRespTime;;
				this->scheduledReports.push_back(reportpacket);
				this->scheduled = true;
				this->reply_timer->initialize(this);
				this->reply_timer->schedule_after_msec(this->countdown);
				click_chatter("Sending reply after %d ms\n", this->countdown);
				
			}
			else{
				this->PacketMerge(reportpacket);
				click_chatter("shit hit fan");
			}
			//output(1).push(reportpacket);

		}			
		/*if(not pushed){
			output(2).push(p);
		}*/		
		
	}


	void InterfaceElement::PacketMerge(Packet* reportpacket){

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
		}
    }
	void InterfaceElement::add_handlers(){
        add_write_handler("Join", &Join, (void*)0);
		add_write_handler("Leave", &Leave, (void*)0);
    }

	


CLICK_ENDDECLS
EXPORT_ELEMENT(InterfaceElement)
