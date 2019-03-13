//#include <iostream>
//#include "scitokens.h"
#include "httpd.h"
#include "mod_auth.h"
#include "apr_lib.h"
#include "apr_strings.h"
#include "http_log.h"
#include "http_request.h"
#include <scitokens-cpp/src/scitokens.h>
#include <unistd.h>//new3/7
//#include <scitokens/scitokens.h>

//using namespace std;  // NOLINT

//todo parse request, apr_table_get
module AP_MODULE_DECLARE_DATA auth_scitoken26_module;

int numberofissuer = 1;
int Scitoken26Verify(request_rec *r, const char *require_line, const void *parsed_require_line) {
  SciToken scitoken;
  char *err_msg;
  char *null_ended_list[numberofissuer+1];
  const char *auth_line, *auth_scheme;
  auth_line = apr_table_get(r->headers_in,"Authorization");//TODO, proxy?
  auth_scheme = ap_getword(r->pool, &auth_line, ' ');// parsing/ pool~
  if (strcasecmp(auth_scheme, "Bearer")){
    ap_log_rerror(APLOG_MARK, APLOG_INFO, 0, r, "wrong scheme", r->uri);
    return AUTHZ_DENIED;
  }
  /* Skip leading spaces. (after scitoken) */ //"\n?"
  //auth_line += 5;
  while (apr_isspace(*auth_line)) {
  auth_line++;
  }
  if(sizeof(auth_line)>1000*1000){
    ap_log_rerror(APLOG_MARK, APLOG_INFO, 0, r, "SciToken too large", r->uri);
    return AUTHZ_DENIED;
  }
  
  //TO DO: Load issuer from module config
  null_ended_list[0] = "https://demo.scitokens.org";
  null_ended_list[1] = NULL;
  ap_log_rerror(APLOG_MARK, APLOG_INFO, 0, r, auth_line, r->uri);
  scitoken_deserialize(auth_line, &scitoken, null_ended_list, &err_msg);
  ap_log_rerror(APLOG_MARK, APLOG_INFO, 0, r, err_msg, r->uri);
  if(scitoken_deserialize(auth_line, &scitoken, null_ended_list, &err_msg)){
    ap_log_rerror(APLOG_MARK, APLOG_INFO, 0, r, "Failed to deserialize scitoken", r->uri);
    ap_log_rerror(APLOG_MARK, APLOG_INFO, 0, r, err_msg, r->uri);
    return AUTHZ_DENIED;
  }
  char* issuer_ptr = NULL;
  if(scitoken_get_claim_string(scitoken, "iss", &issuer_ptr, &err_msg)) {
    ap_log_rerror(APLOG_MARK, APLOG_INFO, 0, r, "Failed to get issuer from token: %s\n",err_msg, r->uri);
    ap_log_rerror(APLOG_MARK, APLOG_INFO, 0, r, err_msg, r->uri);
    return AUTHZ_DENIED;
  }
  
  Enforcer enf;
  char hostname[1024];
  const char* aud_list[2];
  
  if (gethostname(hostname, 1024) != 0) {
    ap_log_rerror(APLOG_MARK, APLOG_INFO, 0, r, "Failed to get hostname", r->uri);
    return AUTHZ_DENIED;
  }
  aud_list[0] = hostname;
  aud_list[1] = NULL;
  
  if (!(enf = enforcer_create(issuer_ptr, aud_list, &err_msg))) {
    ap_log_rerror(APLOG_MARK, APLOG_INFO, 0, r, "Failed to create enforcer",err_msg, r->uri);
    ap_log_rerror(APLOG_MARK, APLOG_INFO, 0, r, err_msg, r->uri);
    return AUTHZ_DENIED;
  }
  
  Acl acl;
  acl.authz = "read";
  //acl.resource = issuers[issuer].c_str();
  
  if (enforcer_test(enf, scitoken, &acl, &err_msg)) {
    ap_log_rerror(APLOG_MARK, APLOG_INFO, 0, r, "Failed enforcer test",err_msg, r->uri);
    ap_log_rerror(APLOG_MARK, APLOG_INFO, 0, r, err_msg, r->uri);
    return AUTHZ_DENIED;
  }
  
  char *str = malloc(strlen("token") + strlen(auth_line) + 1); // +1 for the null-terminator
  // in real code you would check for errors in malloc here
  strcpy(str, "token");
  strcat(str, auth_line);
  ap_log_rerror(APLOG_MARK, APLOG_INFO, 0, r, str, r->uri);
  free(str);
  return AUTHZ_GRANTED;
  
  ap_set_content_type(r, "text/html");
  ap_rprintf(r, "<h2>Hello, %s!</h2>", r->useragent_ip);
}
//apache hooks
static const authz_provider Scitoken26_Provider =
  {
    &Scitoken26Verify,
    NULL,
  };
static void register_hooks(apr_pool_t *p)
{
  ap_register_auth_provider(p, AUTHZ_PROVIDER_GROUP, "Scitoken26",
			    AUTHZ_PROVIDER_VERSION,
			    &Scitoken26_Provider,
			    AP_AUTH_INTERNAL_PER_CONF);
}
AP_DECLARE_MODULE(auth_scitoken26) =// .load filename? module name
{
  STANDARD20_MODULE_STUFF,
  NULL, /* dir config creater TODO*/
  NULL,   /* dir merger -- default is to override TODO*/
  NULL,                        /* server config */
  NULL,                        /* merge server config */
  NULL,              /* command apr_table_t TODO*/
  register_hooks               /* register hooks */
};
