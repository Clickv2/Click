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
#include "RouterInterfaceConnector.hh"

#include <set>

#include <iostream>
using namespace std;

CLICK_DECLS

int RouterInterfaceConnector::configure(Vector<String> & conf, ErrorHandler * errh){
	if (cp_va_kparse(conf, this, errh, cpEnd) < 0){
		return -1;
	}
	return 0;
}

RouterInterfaceConnector::RouterInterfaceConnector(){}
RouterInterfaceConnector::~RouterInterfaceConnector(){}

void RouterInterfaceConnector::logonElement(RouterInterface* interface){
	f_interfaces.push_back(interface);
}

GroupReportGenerator RouterInterfaceConnector::getQueryResponse(){
	GroupReportGenerator gen = GroupReportGenerator();
	gen.makeNewPacket(REPORTMESSAGE);
	set<String> addresses;
	for (int i = 0; i < f_interfaces.size(); i++){
		RouterInterface* currentInterface = f_interfaces.at(i);
		for (int j = 0; j < currentInterface->f_state.size(); j++){
			if (currentInterface->f_state.at(j).f_filterMode == MODE_IS_INCLUDE){
				continue;
			}

			IPAddress ip = currentInterface->f_state.at(j).f_ip;
			addresses.insert(ip.unparse().c_str());
		}
	}
	for (set<String>::iterator it = addresses.begin(); it != addresses.end(); it++){
		gen.addGroupRecord(MODE_IS_EXCLUDE, 0, IPAddress(*it).in_addr(), Vector<struct in_addr>());
	}

	return gen;
}

CLICK_ENDDECLS
EXPORT_ELEMENT(RouterInterfaceConnector)
