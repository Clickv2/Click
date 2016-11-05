#include "GroupRecord.hh"

#include <click/config.h>
#include <click/confparse.hh>
#include <click/error.hh>
#include <clicknet/ip.h>
#include <clicknet/ether.h>
#include <clicknet/igmp.h>
#include <click/timer.hh>

CLICK_DECLS

GroupRecord::GroupRecord(uint8_t recordType, uint8_t auxDataLen, uint16_t nrOfSources,
	struct in_addr multicastAddress, const Vector<struct in_addr>& sourceAddr){

	f_recordType = recordType;
	f_auxDataLen = auxDataLen;
	f_nrOfSources = nrOfSources;
	f_multicastAddress = multicastAddress;

	f_sourceList.clear();
	for (unsigned int i = 0; i < sourceAddr.size(); i++){
		f_sourceList.insert(f_sourceList.end(), sourceAddr.at(i););
	}
}

GroupRecord::~GroupRecord(){}

uint8_t GroupRecord::getType() const{
	return f_recordType;
}
uint8_t GroupRecord::getAuxDataLen() const{
	return f_auxDataLen;
}

uint16_t GroupRecord::getNrOfSources() const{
	return nrOfSources;
}

struct in_addr GroupRecord::getMulticastIp() const{
	return multicastAddress;
}

const Vector<struct in_addr>& GroupRecord::getSourceList() const{
	return f_sourceList;
}

CLICK_ENDDECLS