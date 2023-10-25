#include <string.h>
#include <iostream>

#include "ra_config.h"
#include "tee/ra_quote.h"


extern "C"
void do_epid_ra(uint8_t data[64], char * report, char * signature, char * signing_cert) {
  // 64 Byte report data to embed in the intel-signed report
  sgx_report_data_t report_data = {0};
  for (int i = 0; i < 64; ++i) {
      report_data.d[i] = data[i];
      // std::cout << "data[" << i << "]: " << (int) report_data.d[i] << std::endl; 
   }

  // Don't need to set IAS key/cert when we used accesskey authentication
  RaIasServerCfg ias_server;
  ias_server.endpoint = RA_CONF_STR(kConfIasServer);
  ias_server.accesskey = RA_CONF_STR(kConfIasAccessKey);
  std::string spid = RA_CONF_STR(kConfSPID);

  ra::occlum::RaEnclaveQuote ra;
  ra::occlum::RaIasReport ias_report;
  int ret = ra.GetEnclaveIasReport(ias_server, spid, report_data, &ias_report);
  if (ret) {
    printf("Fail to get quote or fetch report, error code is %x!\n", ret);
  } else {
    // Write the IAS return values to the input buffers
    strcpy(report, ias_report.response_body().c_str());
    strcpy(signature, ias_report.b64_signature().c_str());
    strcpy(signing_cert, ias_report.signing_cert().c_str());
  }
}