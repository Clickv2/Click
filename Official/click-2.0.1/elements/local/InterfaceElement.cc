#include <click/config.h>
#include <click/confparse.hh>
#include <click/error.hh>
#include "GroupRecordGenerator.hh"
#include <clicknet/ip.h>
#include <clicknet/ether.h>
#include <click/timer.hh>
#include "InterfaceElement.hh"

#include <time.h>
#include <stdlib.h>


CLICK_DECLS

    interface_record::interface_record(struct in_addr multicastAddress, filter_mode FilterMode, Vector<struct in_addr> *sourcelist){
		this->multicastAddress = multicastAddress;
		this->FilterMode= FilterMode;
		this->sourcelist = sourcelist;
	}


	InterfaceElement::InterfaceElement(){
		this->filterchange = false;
	}

	InterfaceElement::~InterfaceElement(){

	}


	void InterfaceElement::push(int port, Packet* p){
		click_ip *ipHeader = (click_ip *)p->data();
		IPAddress f_dst = ipHeader->ip_dst;
		/*if(f_dst == IPAddress("224.0.0.1")){
			output(0).push(p);
		}*/
		if(f_dst == this->interfaceaddress){//myIP address
			output(0).push(p);
		}else{ 
			bool pushed = false;
			for(int i = 0; i < this->state.size();i++){
				IPAddress comp = IPAddress(this->state[i]->multicastAddress);
				if (f_dst == this->state[i]->multicastAddress && this->state[i]->FilterMode == EXCLUDE){
					output(0).push(p);
				}
			}			
			/*if(not pushed){
				output(2).push(p);
			}*/		
		}
	}

	int InterfaceElement::configure(Vector<String> & conf, ErrorHandler *errh){
		IPAddress interfaceAddress;
		if(cp_va_kparse(conf, this, errh, "ADDRESS", cpkM, cpIPAddress, &interfaceAddress, cpEnd) < 0){
			return -1;
		}
		this->interfaceaddress = interfaceAddress;
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
		for(int i =0;i < me->state.size();i++){
			if(me->state[i]->multicastAddress == multicastAddressin){
				me->state[i]->FilterMode = INCLUDE;
				me->state[i]->sourcelist->clear();
			}
		}
		reportgenerator.makeNewPacket(REPORTMESSAGE);
		reportgenerator.addGroupRecord(CHANGE_TO_INCLUDE, 0, multicastAddressin, Vector<struct in_addr>());
		Packet* reportpacket = reportgenerator.getCurrentPacket();
		me->output(1).push(reportpacket);
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
		for(int i =0;i < me->state.size();i++){
			if(me->state[i]->multicastAddress == multicastAddressin){
				me->state[i]->FilterMode = EXCLUDE;
				me->state[i]->sourcelist->clear();
				present = true;
			}
		}
		if(not present){
			Vector<struct in_addr> *sourcelist = new Vector<struct in_addr>();
			interface_record *newInterfacerec = new interface_record(multicastAddressin, EXCLUDE, sourcelist);
			me->state.push_back(newInterfacerec);
		}
		reportgenerator.makeNewPacket(REPORTMESSAGE);
		reportgenerator.addGroupRecord(CHANGE_TO_EXCLUDE, 0, multicastAddressin, Vector<struct in_addr>());
		Packet* reportpacket = reportgenerator.getCurrentPacket();
		me->output(1).push(reportpacket);
    }
	void InterfaceElement::add_handlers(){
        add_write_handler("Join", &Join, (void*)0);
		add_write_handler("Leave", &Leave, (void*)0);
    }



CLICK_ENDDECLS
EXPORT_ELEMENT(InterfaceElement)
