#include <click/config.h>
#include <click/confparse.hh>
#include <click/error.hh>
#include "GroupRecordGenerator.hh"
#include <clicknet/ip.h>
#include <clicknet/ether.h>
#include <clicknet/igmp.h>
#include <click/timer.hh>

CLICK_DECLS


GroupRecordGenerator::GroupRecordGenerator(){
	f_recordType = 0;
	f_auxDataLen = 0;
	f_nrOfSources = 0;
	f_addressesGiven = 0;
	f_multicastAddress = 0;
	f_makingRecord = false;
}

GroupRecordGenerator::~GroupRecordGenerator(){
	this->flushPreviousRecord();
}

bool GroupRecordGenerator::initNewRecord(uint8_t recordType, uint8_t auxDataLen, uint16_t nrOfSources, click_ip multicastAddress){
	/// Flush previous record data
	this->flushPreviousRecord();

	/// Set record type if valid
	if (recordType != MODE_IS_INCLUDE || recordType != MODE_IS_EXCLUDE
		|| recordType != CHANGE_TO_INCLUDE || recordType != CHANGE_TO_EXCLUDE){
		return false;
	}
	this->f_recordType = recordType;

	/// Set the auxiliary data length
	this->f_auxDataLen = auxDataLen;

	/// Set the number of sources
	if (!SUPPRESS_OUTPUT && nrOfSources != 0){
		fprintf(stdout, "nrOfSources is non-zero!\n", "%s");
	}
	this->f_nrOfSources = nrOfSources;

	/// Set the multicast address
	this->f_multicastAddress = multicastAddress;

	/// Init an empty source list
	this->f_sourceList.clear();

	/// Indicate that a valid record is being made
	f_makingRecord = true;

	return true;
}

bool GroupRecordGenerator::addSourceAddress(click_ip unicastAddress){
	f_sourceList.insert(f_sourceList.end(), unicastAddress);
	f_addressesGiven++;
	return true;
}

GroupRecord* GroupRecordGenerator::getCurrentRecord() const{
	/// Note: this returns a copy of the current made record
	/// This grouprecord is now responsible for deleting itself properly
	/// returns a nullpointer if the current record would be invalid
	if (f_makingRecord && f_addressesGiven == f_sourceList.size()){
		/// TODO adjust this to a correct record
		return 0;
	}else{
		return 0;
	}
}

void GroupRecordGenerator::flushPreviousRecord(){
	f_recordType = 0;
	f_auxDataLen = 0;
	f_nrOfSources = 0;
	f_addressesGiven = 0;
	f_multicastAddress = 0;
	f_makingRecord = false;
}

uint8_t f_recordType;
uint8_t f_auxDataLen;
uint16_t f_nrOfSources;
click_ip* f_multicastAddress;

uint16_t f_addressesGiven;

CLICK_ENDDECLS