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
#include <iostream>


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

	int InterfaceElement::configure(Vector<String> & conf, ErrorHandler *errh){
		if(cp_va_kparse(conf, this, errh, cpEnd) < 0){
			return -1;
		}
		return 0;
	}


	int InterfaceElement::Leave(const String &conf, Element *e, void* thunk, ErrorHandler *errh){
		InterfaceElement *me = (InterfaceElement* ) e;
		struct in_addr multicastAddressin;
        if(cp_va_kparse(conf, e, errh,
					 "MULTICAST-ADDR", cpkM, cpIPAddress, &multicastAddressin,
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
	}


	int InterfaceElement::Join(const String &conf, Element *e, void* thunk, ErrorHandler *errh){
		InterfaceElement *me = (InterfaceElement* ) e;
		struct in_addr multicastAddressin;
        if(cp_va_kparse(conf, me, errh,
					 "MULTICAST-ADDR", cpkM, cpIPAddress, &multicastAddressin,
					 //"SOURCELIST",  0, Vector<cpIPAddress>, sourcelist,
					  cpEnd) < 0){

            return -1;
        }
		//struct interface_record record = {multicastAddressin, FilterMode, sourcelist};
		//interface.append(record)


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
		
    }
	void InterfaceElement::add_handlers(){
        add_write_handler("Join", &InterfaceElement::Join);
		add_write_handler("Leave", &InterfaceElement::Leave);
    }



CLICK_ENDDECLS
EXPORT_ELEMENT(InterfaceElement)
