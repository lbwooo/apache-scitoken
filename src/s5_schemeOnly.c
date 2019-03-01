//#include <iostream>
//#include "scitokens.h"
#include "httpd.h"
#include "mod_auth.h"
#include "apr_lib.h"
#include "apr_strings.h"
#include "http_log.h"
#include "http_request.h"

//todo parse request, apr_table_get
module AP_MODULE_DECLARE_DATA auth_scitoken5_module;
int Scitoken5Verify(request_rec *r, const char *require_line, const void *parsed_require_line) {
  const char *auth_line, *auth_scheme;
  auth_line = apr_table_get(r->headers_in,"Authorization");//TODO, proxy?
  auth_scheme = ap_getword(r->pool, &auth_line, ' ');// parsing/ pool~
  if (strcasecmp(auth_scheme, "scitoken")){
    ap_log_rerror(APLOG_MARK, APLOG_INFO, 0, r, "wrong scheme", r->uri);
    return AUTHZ_DENIED;
  }
  /* Skip leading spaces. (after scitoken) */
  //while (apr_isspace(*auth_line)) {
  //auth_line++;
  //}
  /* Skip leading spaces. (after scitoken) */
  //auth_line += 9;
  //if(auth_line=="123"){
  if((!strcasecmp(auth_line,"123"))||(!strcasecmp(auth_line," 123"))){
    ap_set_content_type(r, "text/html");
    ap_rprintf(r, "<h2>Hello, %s!</h2>", r->useragent_ip);
    return AUTHZ_GRANTED;
  }
  // str[80];
  //strcat(str, "invalid token");
  char *str = malloc(strlen("invalid token") + strlen(auth_line) + 1); // +1 for the null-terminator
  // in real code you would check for errors in malloc here
  strcpy(str, "invalid token");
  strcat(str, auth_line);
  ap_log_rerror(APLOG_MARK, APLOG_INFO, 0, r, str, r->uri);
  free(str);
  return AUTHZ_DENIED;
}


//apache hooks
static const authz_provider Scitoken5_Provider =
  {
    &Scitoken5Verify,
    NULL,
  };


static void register_hooks(apr_pool_t *p)
{
  ap_register_auth_provider(p, AUTHZ_PROVIDER_GROUP, "Scitoken5",
			    AUTHZ_PROVIDER_VERSION,
			    &Scitoken5_Provider,
			    AP_AUTH_INTERNAL_PER_CONF);
}

AP_DECLARE_MODULE(auth_scitoken5) =// .load filename? module name
{
  STANDARD20_MODULE_STUFF,
  NULL, /* dir config creater TODO*/
  NULL,   /* dir merger -- default is to override TODO*/
  NULL,                        /* server config */
  NULL,                        /* merge server config */
  NULL,              /* command apr_table_t TODO*/
  register_hooks               /* register hooks */
};