# RBAC on the existing services: endpoint to permission map

Generated from `gen/endpoints.py` (one row per handler method, endpoint list from the project docs `10-<service>.md`).
Every row was checked: the permission codes exist in the admin-services catalogue, and at least one role in the
default matrix reaches every user-facing endpoint.

| Service | Endpoints | Enable in |
|---|---|---|
| job-services | 34 | Step 1 (smallest blast radius) |
| candidate-services | 73 | Step 2 |
| vendor-services | 24 | Step 3 |
| notification-services | 2 | Step 4 (internal only) |
| auth-services | 40 | Step 5, own security config, see section 7 |
| workflow-services, task-services | 0 | Nothing to annotate (no controllers yet) |
| gateway, discovery, azure-ad | n/a | No business endpoints |

## 1. What an annotation looks like

Plain Spring Security expressions, nothing custom. The shared filter (`smartie-common-utils`, package
`com.ags.health.hr.common.rbac`) turns every permission of the user into an authority (`JOB:VIEW`) and every role
into `ROLE_<code>` (`ROLE_RECRUITER`), so the built-ins work as they are:

```java
@PreAuthorize("hasAuthority('JOB:CREATE')")                                       // one permission
@PreAuthorize("hasAnyAuthority('CANDIDATE:UPDATE', 'CANDIDATE_SELF:UPDATE')")      // any of them
@PreAuthorize("hasAnyAuthority('APPLICATION:VIEW', 'APPLICATION_SELF:VIEW') or hasRole('INTERNAL')")  // a user with one, or another service
@PreAuthorize("hasRole('INTERNAL')")                                              // other services only
@PreAuthorize("hasRole('INTERNAL') or (hasAuthority('CANDIDATE:CREATE') and hasAuthority('APPLICATION:CREATE'))")
@PreAuthorize("permitAll()")                                                      // public; also list it in public-paths
```

- **Permissions, not roles, on business endpoints.** `hasRole('RECRUITER')` would hard-code today's matrix into the
  code; `hasAuthority('JOB:VIEW')` lets the admin screen change who can do what. Use `hasRole` only for
  `INTERNAL` and for the admin-services rules that are about the role itself (`hasRole('SUPER_ADMIN')`).
- **Internal calls:** a request with a valid `X-Internal-Key` header gets `ROLE_INTERNAL`. If it also forwards the
  user's JWT, the user's permissions stay too, so the callee still knows who the user is. A wrong key is a 401,
  never silently ignored.
- **Coarse check only:** `@PreAuthorize` answers "may this person call this endpoint at all". Rows tagged
  *own record check* still need `AccessEvaluator` inside the method (C permissions, IDOR). Rows tagged
  *ScopeFilter on rows* need the list filtered by OWN / TEAM / LOB / LOCATION (tracker #5 / #7).

## 2. Per-service checklist (do all of it before `RBAC_ENABLED=true`)

1. **pom:** `spring-boot-starter-security`, `jjwt-api`, `jjwt-impl` (runtime), `jjwt-jackson` (runtime), all 0.11.5.
   `smartie-common-utils` is already a dependency.
2. **Make every handler method `public`.** Most controllers declare them `private`. Once method security proxies
   the controller, a private handler is invoked on the proxy: the `@PreAuthorize` is skipped AND every injected
   service is `null` (NPE on the first call). This is the most likely day-one outage, and the test below catches it.
3. **Annotate** every method with the expression from the tables below.
4. **application.yml**

   ```yaml
   smartie:
     rbac:
       enabled: ${RBAC_ENABLED:false}            # flip per environment after the test passes
       jwt-secret: ${JWT_SECRET}
       internal-api-key: ${INTERNAL_API_KEY}
       admin-service-url: ${ADMIN_SERVICE_URL:http://localhost:8989/admin-services}
       public-paths: []                          # job-services: [/jobs/seo/**]
   ```

5. **Internal calls:** add the interceptor to the RestTemplate that calls other smartie-core services (not the
   one for Oracle, Versant, Moodle, SES, Graph):

   ```java
   @Bean
   RestTemplate restTemplate(RbacProperties rbac, @Value("${spring.application.name}") String app) {
       RestTemplate rt = new RestTemplate();
       rt.getInterceptors().add(new RbacInternalCallInterceptor(rbac.getInternalApiKey(), app));
       return rt;
   }
   ```

   Client URLs default to the gateway (`http://localhost:8980/...`). The gateway demands a user JWT, so a call with
   only the internal key (crons: `ApplicationArchiveCron`, `VersantStatusUpdateCron`, `ReadMailAttachmentCron`)
   is rejected there. Point internal clients at the service itself (Eureka `lb://` with `@LoadBalanced`, or the
   service port). Once nothing internal goes through the gateway, add `RemoveRequestHeader=X-Internal-Key` to the
   gateway default filters so a browser can never present the key.
6. **Test** (copy into each service):

   ```java
   @SpringBootTest(properties = {"smartie.rbac.enabled=true", "smartie.rbac.jwt-secret=c2VjcmV0LWtleS1mb3ItdGVzdHMtb25seS0zMi1ieXRlcy1sb25nISE=",
           "smartie.rbac.internal-api-key=test", "eureka.client.enabled=false"})
   class EndpointSecurityTest {
       @Autowired RequestMappingHandlerMapping mapping;

       @Test
       void everyEndpointIsGuardedPublicAndKnown() {
           assertThat(RbacEndpointAudit.violations(mapping, RbacEndpointAudit.knownCodes())).isEmpty();
       }
   }
   ```

   It fails on: a handler without `@PreAuthorize`, a handler that is not public, and a permission code that is not
   in the admin-services catalogue (a typo would deny everybody, silently).
7. **Replace userType checks** inside controllers with permissions (section 5), or the two systems disagree.

## 3. Decide before enabling: who loses access on day one

Users without an admin-services record get fallback roles by `userType`. With the default matrix, these
endpoints start returning 403 for them. Every one of them is either intended by the access matrix or a gap to
fix in the matrix (admin screen) before the flag goes on.


**job-services**

| userType (fallback role) | Blocked | Endpoints |
|---|---|---|
| EMPLOYEE_HR (RECRUITER) | 15 of 34 | `PUT /jobs/{jobid}/activate`, `PUT /jobs/{jobid}/deactivate`, `DELETE /jobs/{jobid}`, `POST /jobs/create`, `PUT /jobs/update/{jobid}`, `PUT /jobs/configure`, `POST /jobs/upload/image/{jobId}`, `DELETE /jobs/delete/image/{jobId}`, `POST /job/populate`, `POST /jobs/upload`, `PUT /jobs/update/{id}/desc`, `POST /requisition/upload`, `POST /requisition/job/create`, `PUT /requisition/job/update`, `GET /populatejobs` |
| EMPLOYEE_HR_ADMIN (RECRUITMENT_MANAGER) | 2 of 34 | `POST /job/populate`, `GET /populatejobs` |
| EMPLOYEE_NON_HR (EMPLOYEE) | 27 of 34 | `GET /jobs`, `PUT /jobs/{jobid}/activate`, `PUT /jobs/{jobid}/deactivate`, `DELETE /jobs/{jobid}`, `POST /jobs/create`, `PUT /jobs/update/{jobid}`, `PUT /jobs/configure`, `POST /jobs/vendor/search`, `POST /jobs/upload/image/{jobId}`, `DELETE /jobs/delete/image/{jobId}`, `POST /job/populate`, `GET /jobs/all`, `POST /jobs/upload`, `GET /jobs/report/download`, `PUT /jobs/update/{id}/desc`, `POST /requisition/upload`, `POST /requisition/job/create`, `PUT /requisition/job/update`, `POST /requisition/job/filter`, `GET /requisition/job/get/{requisitionid}` ... (+7) |
| VENDOR (VENDOR) | 18 of 34 | `PUT /jobs/{jobid}/activate`, `PUT /jobs/{jobid}/deactivate`, `DELETE /jobs/{jobid}`, `POST /jobs/create`, `PUT /jobs/update/{jobid}`, `PUT /jobs/configure`, `POST /jobs/upload/image/{jobId}`, `DELETE /jobs/delete/image/{jobId}`, `POST /job/populate`, `POST /jobs/upload`, `GET /jobs/report/download`, `PUT /jobs/update/{id}/desc`, `POST /requisition/upload`, `POST /requisition/job/create`, `PUT /requisition/job/update`, `POST /requisition/job/update/count`, `POST /requisition/job/download`, `GET /populatejobs` |
| CANDIDATE (CANDIDATE) | 27 of 34 | `GET /jobs`, `PUT /jobs/{jobid}/activate`, `PUT /jobs/{jobid}/deactivate`, `DELETE /jobs/{jobid}`, `POST /jobs/create`, `PUT /jobs/update/{jobid}`, `PUT /jobs/configure`, `POST /jobs/vendor/search`, `POST /jobs/upload/image/{jobId}`, `DELETE /jobs/delete/image/{jobId}`, `POST /job/populate`, `GET /jobs/all`, `POST /jobs/upload`, `GET /jobs/report/download`, `PUT /jobs/update/{id}/desc`, `POST /requisition/upload`, `POST /requisition/job/create`, `PUT /requisition/job/update`, `POST /requisition/job/filter`, `GET /requisition/job/get/{requisitionid}` ... (+7) |

**candidate-services**

| userType (fallback role) | Blocked | Endpoints |
|---|---|---|
| EMPLOYEE_HR (RECRUITER) | 11 of 73 | `GET /candidates/me`, `DELETE /candidates/me`, `GET /applications/report.csv`, `POST /applications/vendor/search`, `POST /vendor/application/{vendorid}`, `POST /panel/member/create`, `PUT /panel/member/update`, `PATCH /panel/member/{employeeid}/deactivate`, `PATCH /panel/member/{employeeid}/activate`, `POST /panel/member/upload`, `GET /interview/versant/cron` |
| EMPLOYEE_HR_ADMIN (RECRUITMENT_MANAGER) | 17 of 73 | `GET /candidates/me`, `DELETE /candidates/me`, `POST /applications/vendor/search`, `POST /vendor/application/{vendorid}`, `POST /application/get/panel`, `POST /application/get/pending/panel/v2`, `POST /panel/events`, `POST /panel/event/detail`, `GET /panel/event/{id}/update/history`, `POST /interview/process/status`, `POST /interview/get/details`, `POST /interview/link/status`, `POST /interview/start/panel`, `GET /interview/summary`, `GET /interview/versant/cron`, `PUT /interview/{applicationid}/reintiate`, `GET /interview/application/{applicationid}/clone` |
| EMPLOYEE_NON_HR (EMPLOYEE) | 68 of 73 | `GET /candidates`, `GET /candidates/me`, `GET /candidates/{candidateid}`, `DELETE /candidates/me`, `DELETE /candidates/{candidateid}`, `POST /candidates`, `GET /candidates/search`, `POST /candidates/email/mobile`, `POST /candidates/create/application`, `POST /candidate/get`, `POST /profile/upload`, `POST /profile/add/update/personal/{smartieUserId}`, `POST /profile/add/update/work/{smartieUserId}`, `POST /profile/add/update/work/experience/{smartieUserId}`, `POST /profile/add/update/id/proof/{smartieUserId}`, `POST /profile/add/update/fitment/{smartieUserId}`, `POST /profile/add/update/education/{smartieUserId}`, `GET /profile/get/{smartieuserid}`, `GET /applications`, `GET /applications/{applicationid}` ... (+48) |
| VENDOR (VENDOR) | 69 of 73 | `GET /candidates`, `GET /candidates/me`, `GET /candidates/{candidateid}`, `DELETE /candidates/me`, `DELETE /candidates/{candidateid}`, `POST /candidates`, `GET /candidates/search`, `POST /candidates/email/mobile`, `POST /candidates/create/application`, `POST /candidate/get`, `POST /profile/upload`, `POST /profile/add/update/personal/{smartieUserId}`, `POST /profile/add/update/work/{smartieUserId}`, `POST /profile/add/update/work/experience/{smartieUserId}`, `POST /profile/add/update/id/proof/{smartieUserId}`, `POST /profile/add/update/fitment/{smartieUserId}`, `POST /profile/add/update/education/{smartieUserId}`, `GET /profile/get/{smartieuserid}`, `GET /applications`, `GET /applications/{applicationid}` ... (+49) |
| CANDIDATE (CANDIDATE) | 51 of 73 | `GET /candidates`, `DELETE /candidates/{candidateid}`, `POST /candidates`, `GET /candidates/search`, `POST /candidates/email/mobile`, `POST /candidates/create/application`, `POST /candidate/get`, `POST /profile/upload`, `POST /profile/add/update/fitment/{smartieUserId}`, `GET /applications`, `POST /applications-search`, `POST /applications/search`, `GET /applications/report.csv`, `PUT /hr/applications/update/{applicationid}`, `POST /applications/status`, `POST /applications/vendor/search`, `POST /vendor/application/{vendorid}`, `PUT /application/add/ctc/{applicationid}`, `POST /application/get/panel`, `GET /application/{id}/remarks/history` ... (+31) |

**vendor-services**

| userType (fallback role) | Blocked | Endpoints |
|---|---|---|
| EMPLOYEE_HR (RECRUITER) | 11 of 24 | `POST /vendor/create`, `PUT /vendor/update`, `PUT /vendor/update/status`, `DELETE /vendor/delete/doc/{vendordocid}`, `POST /vendor/{vendorid}/vendordoc/{fileName}`, `POST /hr/vendor/{vendorid}/vendordoc/{fileName}`, `POST /vendor/create/task`, `PUT /vendor/update/task`, `DELETE /vendor/task/deactivate/{vendortaskid}`, `POST /vendor/task/amount`, `POST /vendor/task/updatecost` |
| EMPLOYEE_HR_ADMIN (RECRUITMENT_MANAGER) | 2 of 24 | `POST /vendor/task/amount`, `POST /vendor/task/updatecost` |
| EMPLOYEE_NON_HR (EMPLOYEE) | 24 of 24 | `POST /vendor/create`, `PUT /vendor/update`, `GET /vendor/get/{vendorid}`, `PUT /vendor/update/status`, `POST /vendor/search`, `POST /vendor/application/status`, `DELETE /vendor/delete/doc/{vendordocid}`, `POST /vendor/{vendorid}/vendordoc/{fileName}`, `POST /hr/vendor/{vendorid}/vendordoc/{fileName}`, `GET /vendor/{vendorid}/vendordoc`, `GET /vendor/get/vendorid/{smartieuserid}`, `POST /vendor/create/task`, `PUT /vendor/update/task`, `GET /vendor/task/{vendortaskid}`, `GET /vendor/task/{vendortaskid}/external`, `POST /vendor/task/list/{vendorid}`, `DELETE /vendor/task/deactivate/{vendortaskid}`, `POST /vendor/task/search`, `GET /vendor/task/job/description/{taskid}`, `GET /vendor/task/candidates/{taskid}` ... (+4) |
| VENDOR (VENDOR) | 8 of 24 | `POST /vendor/create`, `PUT /vendor/update/status`, `POST /hr/vendor/{vendorid}/vendordoc/{fileName}`, `POST /vendor/create/task`, `PUT /vendor/update/task`, `DELETE /vendor/task/deactivate/{vendortaskid}`, `POST /vendor/task/amount`, `POST /vendor/task/updatecost` |
| CANDIDATE (CANDIDATE) | 24 of 24 | `POST /vendor/create`, `PUT /vendor/update`, `GET /vendor/get/{vendorid}`, `PUT /vendor/update/status`, `POST /vendor/search`, `POST /vendor/application/status`, `DELETE /vendor/delete/doc/{vendordocid}`, `POST /vendor/{vendorid}/vendordoc/{fileName}`, `POST /hr/vendor/{vendorid}/vendordoc/{fileName}`, `GET /vendor/{vendorid}/vendordoc`, `GET /vendor/get/vendorid/{smartieuserid}`, `POST /vendor/create/task`, `PUT /vendor/update/task`, `GET /vendor/task/{vendortaskid}`, `GET /vendor/task/{vendortaskid}/external`, `POST /vendor/task/list/{vendorid}`, `DELETE /vendor/task/deactivate/{vendortaskid}`, `POST /vendor/task/search`, `GET /vendor/task/job/description/{taskid}`, `GET /vendor/task/candidates/{taskid}` ... (+4) |

Read this table with the business, not alone:

- **Recruiters lose job / requisition create and update.** The architect's matrix gives RECRUITER only `JOB:VIEW`
  and `JOB:MAP`. If recruiters raise requisitions today, add `JOB:CREATE` / `JOB:UPDATE` to RECRUITER on the matrix
  screen first, or this is an outage, not a policy change.
- **Recruitment Managers have no interview permissions** in the matrix (no `INTERVIEW:*`). TL / managers who
  schedule or reschedule interviews today will get 403.
- **Panel members are mostly `EMPLOYEE_NON_HR`, so they fall back to EMPLOYEE**, which has no `INTERVIEW:UPDATE`
  and no `INTERVIEW_FEEDBACK:*`. They can not submit feedback. Two fixes: give every panel member an admin-services
  record with INTERVIEWER (clean), or change the fallback to `EMPLOYEE_NON_HR: [EMPLOYEE, INTERVIEWER]` (quick;
  INTERVIEWER is assignment-only, but every employee then holds the feedback permissions).
- **Vendors and candidates** only reach their own self-service endpoints. That is the point.

## 4. Endpoint tables

Expression = the exact `@PreAuthorize` value. Notes: *own* = own record check in the method, *rows* = ScopeFilter, *confirm* = judgment call or unknown caller.


### job-services (34)

| Controller.method | HTTP | Path | @PreAuthorize | Notes |
|---|---|---|---|---|
| JobPostingController.getAllJobPostings | GET | `/jobs` | `hasAuthority('JOB:VIEW')` | *rows* |
| JobPostingController.getJobPostingDetail | GET | `/jobs/{jobid}` | `hasAnyAuthority('JOB:VIEW', 'JOB_OPPORTUNITY:VIEW', 'EMPLOYEE_REFERRAL:CREATE') or hasRole('INTERNAL')` | Candidates, employees (Buddy Finder) and auth-services' public job proxy read single jobs |
| JobPostingController.getJobPosting | POST | `/jobs/{jobid}` | `hasAnyAuthority('JOB:VIEW', 'JOB_OPPORTUNITY:VIEW', 'EMPLOYEE_REFERRAL:CREATE') or hasRole('INTERNAL')` |  |
| JobPostingController.generateLink | GET | `/jobs/generatelink/{userid}/{jobid}` | `hasAnyAuthority('JOB:VIEW', 'JOB_OPPORTUNITY:VIEW', 'EMPLOYEE_REFERRAL:CREATE')` | *own* userid must be the caller unless JOB:VIEW - today anyone can mint a share link for any user id |
| JobPostingController.activateJobPosting | PUT | `/jobs/{jobid}/activate` | `hasAuthority('JOB:PUBLISH')` |  |
| JobPostingController.deactivateJobPosting | PUT | `/jobs/{jobid}/deactivate` | `hasAuthority('JOB:PUBLISH')` |  |
| JobPostingController.deleteJobPosting | DELETE | `/jobs/{jobid}` | `hasAuthority('JOB:DELETE')` | *own* C for Recruitment Manager: only jobs they own. Hard delete today - consider deactivate |
| JobPostingController.createJobPosting | POST | `/jobs/create` | `hasAuthority('JOB:CREATE')` |  |
| JobPostingController.updateJobPosting | PUT | `/jobs/update/{jobid}` | `hasAuthority('JOB:UPDATE')` |  |
| JobPostingController.configureJobs | PUT | `/jobs/configure` | `hasAuthority('JOB:UPDATE')` |  |
| JobPostingController.getAllESJobPostingsSearch | POST | `/jobs-search` | `hasAnyAuthority('JOB:VIEW', 'JOB_OPPORTUNITY:VIEW', 'EMPLOYEE_REFERRAL:CREATE') or hasRole('INTERNAL')` | *rows* |
| JobPostingController.getAllESJobPostings | POST | `/jobs/search` | `hasAnyAuthority('JOB:VIEW', 'JOB_OPPORTUNITY:VIEW', 'EMPLOYEE_REFERRAL:CREATE') or hasRole('INTERNAL')` | *rows* Called by auth-services public /jobs/search proxy |
| JobPostingController.getAllESJobPostingsVendor | POST | `/jobs/vendor/search` | `hasAuthority('JOB:VIEW')` | *rows* Vendor holds JOB:VIEW as C: only jobs with a vendor task for that vendor |
| JobPostingController.getJobDetails | GET | `/jobs/seo/{jobid}` | `permitAll()` | Public SEO page. Also add /jobs/seo/** to smartie.rbac.public-paths |
| JobPostingController.uploadFile | POST | `/jobs/upload/image/{jobId}` | `hasAuthority('JOB:UPDATE')` |  |
| JobPostingController.deleteFile | DELETE | `/jobs/delete/image/{jobId}` | `hasAuthority('JOB:UPDATE')` |  |
| JobPostingController.populateJobs | POST | `/job/populate` | `hasAuthority('INTEGRATION:UPDATE') or hasRole('INTERNAL')` | Elasticsearch re-index. Super Admin or a scheduled job |
| JobPostingController.getAllJobs | GET | `/jobs/all` | `hasAuthority('JOB:VIEW')` | *rows* |
| JobPostingController.uploadJobDetails | POST | `/jobs/upload` | `hasAuthority('JOB:CREATE')` |  |
| JobPostingController.jobReportDownLoad | GET | `/jobs/report/download` | `hasAuthority('REPORT:VIEW')` | *confirm* fileName request param: check it can only name a generated report (path traversal) |
| JobPostingController.updateJobPostingDescription | PUT | `/jobs/update/{id}/desc` | `hasAuthority('JOB:EDIT_JD')` | BRD: JD edits need TA Head approval - approval flow is tracker #6/#8 |
| JobPostingController.getAllJobPostingsSearchV2 | GET | `/jobs/search/v2` | `hasAnyAuthority('JOB:VIEW', 'JOB_OPPORTUNITY:VIEW', 'EMPLOYEE_REFERRAL:CREATE') or hasRole('INTERNAL')` | *rows* |
| JobRequisitionController.uploadRequisition | POST | `/requisition/upload` | `hasAuthority('JOB:CREATE')` |  |
| JobRequisitionController.createJobRequisition | POST | `/requisition/job/create` | `hasAuthority('JOB:CREATE')` |  |
| JobRequisitionController.updateJobRequisition | PUT | `/requisition/job/update` | `hasAuthority('JOB:UPDATE')` |  |
| JobRequisitionController.filterJobRequisition | POST | `/requisition/job/filter` | `hasAuthority('JOB:VIEW')` | *rows* |
| JobRequisitionController.getJobRequisitionById | GET | `/requisition/job/get/{requisitionid}` | `hasAuthority('JOB:VIEW') or hasRole('INTERNAL')` | candidate-services reads requisitions |
| JobRequisitionController.updateRequisitionCount | POST | `/requisition/job/update/count` | `hasAnyAuthority('JOB:MAP', 'APPLICATION:MAP') or hasRole('INTERNAL')` | Changes when a candidate is mapped to the requisition |
| JobRequisitionController.getRequisitionByIds | POST | `/requisition/job/list` | `hasAuthority('JOB:VIEW') or hasRole('INTERNAL')` |  |
| JobRequisitionController.getRemarksList | GET | `/requisition/job/remarks/{requisitionid}/list` | `hasAuthority('JOB:VIEW')` |  |
| JobRequisitionController.getRemarkImage | GET | `/requisition/job/remarks/{remarkid}/image` | `hasAuthority('JOB:VIEW')` |  |
| JobRequisitionController.downloadRequisition | POST | `/requisition/job/download` | `hasAuthority('REPORT:VIEW')` | *rows* Export: same row filter as the list |
| JobRequisitionController.getSourceCount | GET | `/requisition/job/source/count` | `hasAuthority('JOB:VIEW')` |  |
| OracleController.populateJobs | GET | `/populatejobs` | `hasAuthority('INTEGRATION:UPDATE') or hasRole('INTERNAL')` | *confirm* GET that writes data. Make it POST when touching it |

### candidate-services (73)

| Controller.method | HTTP | Path | @PreAuthorize | Notes |
|---|---|---|---|---|
| CandidateController.getAllCandidates | GET | `/candidates` | `hasAuthority('CANDIDATE:VIEW')` | *rows* Unpaged list of every candidate. Page it and apply ScopeFilter |
| CandidateController.getMyCandidateProfile | GET | `/candidates/me` | `hasAuthority('CANDIDATE_SELF:VIEW')` |  |
| CandidateController.getCandidate | GET | `/candidates/{candidateid}` | `hasAnyAuthority('CANDIDATE:VIEW', 'CANDIDATE_SUMMARY:VIEW', 'CANDIDATE_SELF:VIEW') or hasRole('INTERNAL')` | *own* Keep validateUserAuthorization, but replace the userType test with AccessEvaluator (see section 4) |
| CandidateController.deleteMyCandidateProfile | DELETE | `/candidates/me` | `hasAuthority('CANDIDATE_SELF:DELETE')` | *confirm* Matrix says 'close account'. Code hard-deletes - business must confirm |
| CandidateController.deleteCandidate | DELETE | `/candidates/{candidateid}` | `hasAuthority('CANDIDATE:DELETE')` | *own* C for Recruiter / Recruitment Manager |
| CandidateController.saveCandidate | POST | `/candidates` | `hasAuthority('CANDIDATE:CREATE') or hasRole('INTERNAL')` | Registration path creates candidates through auth-services |
| CandidateController.getCandidateByUsername | GET | `/candidates/search` | `hasAuthority('CANDIDATE:VIEW') or hasRole('INTERNAL')` | auth-services CandidateClient calls it |
| CandidateController.getCandidateByEmailOrMobile | POST | `/candidates/email/mobile` | `hasAnyAuthority('CANDIDATE:VIEW', 'CANDIDATE:CREATE') or hasRole('INTERNAL')` | Duplicate check before create |
| CandidateController.createCandidateWithApplication | POST | `/candidates/create/application` | `hasRole('INTERNAL') or (hasAuthority('CANDIDATE:CREATE') and hasAuthority('APPLICATION:CREATE'))` |  |
| CandidateController.getCandidatesList | POST | `/candidate/get` | `hasAnyAuthority('CANDIDATE:VIEW', 'CANDIDATE_SUMMARY:VIEW') or hasRole('INTERNAL')` | Unauthenticated today (20-cross-service 5.3) |
| CandidateController.uploadCandidateDetails | POST | `/profile/upload` | `hasAuthority('CANDIDATE:CREATE')` | Bulk upload |
| CandidateProfileController.addUpdatePersonalDetails | POST | `/profile/add/update/personal/{smartieUserId}` | `hasAnyAuthority('CANDIDATE:UPDATE', 'CANDIDATE_SELF:UPDATE')` | *own* smartieUserId must be the caller unless CANDIDATE:UPDATE |
| CandidateProfileController.addUpdateWorkDetails | POST | `/profile/add/update/work/{smartieUserId}` | `hasAnyAuthority('CANDIDATE:UPDATE', 'CANDIDATE_SELF:UPDATE')` | *own* |
| CandidateProfileController.addUpdateWorkExperienceDetails | POST | `/profile/add/update/work/experience/{smartieUserId}` | `hasAnyAuthority('CANDIDATE:UPDATE', 'CANDIDATE_SELF:UPDATE')` | *own* |
| CandidateProfileController.addUpdateIdProofDetails | POST | `/profile/add/update/id/proof/{smartieUserId}` | `hasAnyAuthority('CANDIDATE:UPDATE', 'CANDIDATE_SELF:UPDATE')` | *own* Reading ID proofs back needs CANDIDATE:VIEW_SENSITIVE (or self) |
| CandidateProfileController.addUpdateFitmentDetails | POST | `/profile/add/update/fitment/{smartieUserId}` | `hasAuthority('CANDIDATE:UPDATE')` | Fitment is the HR assessment - not candidate self-service |
| CandidateProfileController.addUpdateEducationDetails | POST | `/profile/add/update/education/{smartieUserId}` | `hasAnyAuthority('CANDIDATE:UPDATE', 'CANDIDATE_SELF:UPDATE')` | *own* |
| CandidateProfileController.getProfileById | GET | `/profile/get/{smartieuserid}` | `hasAnyAuthority('CANDIDATE:VIEW', 'CANDIDATE_SELF:VIEW') or hasRole('INTERNAL')` | *own* Blank the ID-proof section unless CANDIDATE:VIEW_SENSITIVE or self |
| ApplicationController.getAllApplications | GET | `/applications` | `hasAuthority('APPLICATION:VIEW')` | *rows* Unpaged. Page it and apply ScopeFilter |
| ApplicationController.getApplication | GET | `/applications/{applicationid}` | `hasAnyAuthority('APPLICATION:VIEW', 'APPLICATION_SELF:VIEW') or hasRole('INTERNAL')` | *own* |
| ApplicationController.deleteApplication | DELETE | `/applications/{applicationid}` | `hasAnyAuthority('APPLICATION:DELETE', 'APPLICATION_SELF:DELETE')` | *own, confirm* Self = withdraw: must be a status change, not a delete |
| ApplicationController.saveApplication | POST | `/applications` | `hasAnyAuthority('APPLICATION:CREATE', 'APPLICATION_SELF:CREATE') or hasRole('INTERNAL')` | *own* Candidate may only apply for themselves |
| ApplicationController.updateApplication | PUT | `/applications/{applicationid}` | `hasAnyAuthority('APPLICATION:UPDATE', 'APPLICATION_SELF:UPDATE') or hasRole('INTERNAL')` | *own* |
| ApplicationController.getAllESApplicationsSearch | POST | `/applications-search` | `hasAuthority('APPLICATION:VIEW')` | *rows* Tracker #5 / #7: the main pipeline list |
| ApplicationController.getAllESApplications | POST | `/applications/search` | `hasAuthority('APPLICATION:VIEW')` | *rows* |
| ApplicationController.getReport | GET | `/applications/report.csv` | `hasAuthority('CANDIDATE:EXPORT')` | *rows* Export of candidate data |
| ApplicationController.updateHrApplication | PUT | `/hr/applications/update/{applicationid}` | `hasAuthority('APPLICATION:UPDATE')` | *own* |
| ApplicationController.getApplicationDetailsByCandidateId | GET | `/application/details/{candidateid}` | `hasAnyAuthority('APPLICATION:VIEW', 'APPLICATION_SELF:VIEW') or hasRole('INTERNAL')` | *own* |
| ApplicationController.getAllApplicationsByStatus | POST | `/applications/status` | `hasAnyAuthority('APPLICATION:VIEW', 'CANDIDATE_STATUS:VIEW') or hasRole('INTERNAL')` | *rows* vendor-services calls it |
| ApplicationController.getAllESApplicationsVendor | POST | `/applications/vendor/search` | `hasAnyAuthority('CANDIDATE_SUBMISSION:VIEW', 'CANDIDATE_STATUS:VIEW')` | *rows* Vendor: own submissions only |
| ApplicationController.saveVendorApplication | POST | `/vendor/application/{vendorid}` | `hasAuthority('CANDIDATE_SUBMISSION:CREATE') or hasRole('INTERNAL')` | *own* vendorid must be the caller's vendor |
| ApplicationController.addCtc | PUT | `/application/add/ctc/{applicationid}` | `hasAuthority('APPLICATION:UPDATE')` | *own, confirm* Compensation data. Should offer-stage CTC need SELECTION_OFFER:UPDATE? |
| ApplicationController.getAllApplicationsByPanelMember | POST | `/application/get/panel` | `hasAnyAuthority('INTERVIEW:VIEW', 'INTERVIEW_ASSIGNMENT:VIEW')` | *rows* Panel member: only own assignments |
| ApplicationController.getRemarksHistory | GET | `/application/{id}/remarks/history` | `hasAuthority('APPLICATION:VIEW')` | *own* |
| ApplicationController.hrRejectApplication | PUT | `/application/hr/reject` | `hasAuthority('APPLICATION:REJECT')` | *own* |
| ApplicationController.getPendingPanelListV2 | POST | `/application/get/pending/panel/v2` | `hasAnyAuthority('INTERVIEW:VIEW', 'INTERVIEW_ASSIGNMENT:VIEW')` | *rows* |
| ApplicationController.getApplicationByCandidate | GET | `/application/get/{candidateId}` | `hasAnyAuthority('APPLICATION:VIEW', 'APPLICATION_SELF:VIEW') or hasRole('INTERNAL')` | *own* |
| ApplicationController.archiveApplications | POST | `/applications/archive` | `hasAuthority('APPLICATION:DELETE') or hasRole('INTERNAL')` | auth-services ApplicationArchiveCron calls it |
| DeviceController.addDevice | POST | `/device/add` | `hasAuthority('DEVICE:MANAGE')` |  |
| DeviceController.updateDevice | PUT | `/device/update` | `hasAuthority('DEVICE:MANAGE')` |  |
| DeviceController.allocateDevice | POST | `/device/allocate` | `hasAuthority('DEVICE:MANAGE') or hasRole('INTERNAL')` | auth-services kiosk proxy /interview/device/allocate |
| DeviceController.deAllocateDevice | DELETE | `/device/deallocate/{deviceid}` | `hasAuthority('DEVICE:MANAGE')` |  |
| DeviceController.getAllDevices | GET | `/device/get` | `hasAuthority('DEVICE:VIEW') or hasRole('INTERNAL')` | auth-services kiosk proxy /interview/device/get |
| PanelEventController.getPanelEvents | POST | `/panel/events` | `hasAnyAuthority('INTERVIEW:VIEW', 'INTERVIEW_ASSIGNMENT:VIEW')` | *rows* Replace the userType check at lines 46-52 |
| PanelEventController.getPanelEventDetail | POST | `/panel/event/detail` | `hasAnyAuthority('INTERVIEW:VIEW', 'INTERVIEW_ASSIGNMENT:VIEW')` | *own* |
| PanelEventController.getPanelUpdateHistory | GET | `/panel/event/{id}/update/history` | `hasAuthority('INTERVIEW:VIEW')` |  |
| PanelEventController.getCalendarAvailability | POST | `/panel/get/calendar/availability` | `hasAnyAuthority('INTERVIEW:CREATE', 'APPLICATION:SCHEDULE_INTERVIEW')` | Reads panel members' Outlook calendars |
| PanelMemberController.createPanelMember | POST | `/panel/member/create` | `hasAuthority('PANEL_MEMBER:MANAGE')` |  |
| PanelMemberController.updatePanelMember | PUT | `/panel/member/update` | `hasAuthority('PANEL_MEMBER:MANAGE')` |  |
| PanelMemberController.deactivatePanelMember | PATCH | `/panel/member/{employeeid}/deactivate` | `hasAuthority('PANEL_MEMBER:MANAGE')` |  |
| PanelMemberController.activatePanelMember | PATCH | `/panel/member/{employeeid}/activate` | `hasAuthority('PANEL_MEMBER:MANAGE')` |  |
| PanelMemberController.getAllPanelMember | GET | `/panel/member/get` | `hasAuthority('PANEL_MEMBER:VIEW')` |  |
| PanelMemberController.getAllPanelMemberV2 | POST | `/panel/member/get/v2` | `hasAuthority('PANEL_MEMBER:VIEW')` |  |
| PanelMemberController.uploadFile | POST | `/panel/member/upload` | `hasAuthority('PANEL_MEMBER:MANAGE')` |  |
| PanelMemberController.jobReportDownLoad | GET | `/panel/member/report/download` | `hasAuthority('PANEL_MEMBER:VIEW')` | *confirm* fileName request param: same path traversal check as job reports |
| InterviewController.createInterview | POST | `/interview/create` | `hasAnyAuthority('INTERVIEW:CREATE', 'APPLICATION:SCHEDULE_INTERVIEW') or hasRole('INTERNAL')` | *own* |
| InterviewController.updateInterviewProcessStatus | POST | `/interview/process/status` | `hasAnyAuthority('INTERVIEW:UPDATE', 'INTERVIEW_FEEDBACK:CREATE', 'INTERVIEW_FEEDBACK:UPDATE') or hasRole('INTERNAL')` | *own* Panel member: only interviews assigned to them |
| InterviewController.getInterviewDetails | POST | `/interview/get/details` | `hasAnyAuthority('INTERVIEW:VIEW', 'INTERVIEW_ASSIGNMENT:VIEW', 'INTERVIEW_SCHEDULE:VIEW') or hasRole('INTERNAL')` | *own* Also reached through the auth-services kiosk proxy |
| InterviewController.updateInterviewLinkStatus | POST | `/interview/link/status` | `hasAuthority('INTERVIEW:UPDATE') or hasRole('INTERNAL')` | Kiosk proxy |
| InterviewController.startPanel | POST | `/interview/start/panel` | `hasAuthority('INTERVIEW:UPDATE') or hasRole('INTERNAL')` | *own* Kiosk proxy |
| InterviewController.getAssesmentLink | GET | `/interview/get/assesment/link/{deviceId}` | `hasAnyAuthority('INTERVIEW:VIEW', 'DEVICE:VIEW') or hasRole('INTERNAL')` | Kiosk proxy |
| InterviewController.getInterviewSummary | GET | `/interview/summary` | `hasAnyAuthority('INTERVIEW:VIEW', 'INTERVIEW_FEEDBACK:VIEW', 'OTHER_PANEL_FEEDBACK:VIEW')` | *own* Hide other panels' feedback unless OTHER_PANEL_FEEDBACK:VIEW |
| InterviewController.versantCron | GET | `/interview/versant/cron` | `hasAuthority('INTEGRATION:UPDATE') or hasRole('INTERNAL')` | Manual trigger of the Versant sync |
| InterviewController.reinitiateCandidateInterview | PUT | `/interview/{applicationid}/reintiate` | `hasAuthority('INTERVIEW:UPDATE')` | *own* |
| InterviewController.cloneInterviewDetails | GET | `/interview/application/{applicationid}/clone` | `hasAuthority('INTERVIEW:CREATE')` | *confirm* GET that writes data |
| JobRequisitionController.getHrProcessedJobRequisitionCount | GET | `/requisition/job/{requisitionid}/hr/processcount` | `hasAuthority('JOB:VIEW') or hasRole('INTERNAL')` |  |
| JobRequisitionController.updateHrProcessedJobRequisitionCount | PUT | `/requisition/job/update/processcount` | `hasAnyAuthority('JOB:MAP', 'APPLICATION:MAP') or hasRole('INTERNAL')` |  |
| SmartieProfileController.uploadCV | POST | `/profile/{userid}/cv/{fileName}` | `hasAnyAuthority('CANDIDATE:UPDATE', 'CANDIDATE_SELF:UPDATE')` | *own* Keep the existing self / HR check, swap userType for permissions |
| SmartieProfileController.getCV | GET | `/profile/{userid}/cv` | `hasAnyAuthority('CANDIDATE:VIEW', 'CANDIDATE_SELF:VIEW') or hasRole('INTERNAL')` | *own* Interviewer (CANDIDATE_SUMMARY only) gets no CV: it has PII |
| SmartieProfileController.deleteCV | DELETE | `/profile/{userid}/cv` | `hasAnyAuthority('CANDIDATE:UPDATE', 'CANDIDATE_SELF:UPDATE')` | *own* |
| SmartieProfileController.uploadImage | POST | `/profile/{userid}/image/{fileName}` | `hasAnyAuthority('CANDIDATE:UPDATE', 'CANDIDATE_SELF:UPDATE')` | *own* |
| SmartieProfileController.getImage | GET | `/profile/{userid}/image` | `hasAnyAuthority('CANDIDATE:VIEW', 'CANDIDATE_SUMMARY:VIEW', 'CANDIDATE_SELF:VIEW') or hasRole('INTERNAL')` | *own* Photo is fine for the panel |
| SmartieProfileController.deleteImage | DELETE | `/profile/{userid}/image` | `hasAnyAuthority('CANDIDATE:UPDATE', 'CANDIDATE_SELF:UPDATE')` | *own* |

### vendor-services (24)

| Controller.method | HTTP | Path | @PreAuthorize | Notes |
|---|---|---|---|---|
| VendorController.createVendor | POST | `/vendor/create` | `hasAuthority('VENDOR:CREATE') or hasRole('INTERNAL')` | auth-services /profile/create/vendor may call it |
| VendorController.updateVendor | PUT | `/vendor/update` | `hasAuthority('VENDOR:UPDATE')` | *own* Vendor holds VENDOR:UPDATE as C: own profile only |
| VendorController.getVendorDetail | GET | `/vendor/get/{vendorid}` | `hasAuthority('VENDOR:VIEW') or hasRole('INTERNAL')` | *own* |
| VendorController.updateStatus | PUT | `/vendor/update/status` | `hasAuthority('VENDOR:APPROVE')` |  |
| VendorController.getAllVendors | POST | `/vendor/search` | `hasAuthority('VENDOR:VIEW')` | *rows* |
| VendorController.getAllVendorApplicationsByStatus | POST | `/vendor/application/status` | `hasAnyAuthority('CANDIDATE_STATUS:VIEW', 'APPLICATION:VIEW')` | *rows* |
| VendorController.deleteDocument | DELETE | `/vendor/delete/doc/{vendordocid}` | `hasAuthority('VENDOR:UPDATE')` | *own* Hard delete of a compliance document. Should a vendor be able to delete its own KYC? |
| VendorController.uploadDocument | POST | `/vendor/{vendorid}/vendordoc/{fileName}` | `hasAuthority('VENDOR:UPDATE')` | *own* |
| VendorController.uploadHRDocument | POST | `/hr/vendor/{vendorid}/vendordoc/{fileName}` | `hasAuthority('VENDOR:APPROVE')` | *confirm* HR-only upload: VENDOR:APPROVE keeps vendors out |
| VendorController.getAllDocumentsByVendorId | GET | `/vendor/{vendorid}/vendordoc` | `hasAuthority('VENDOR:VIEW') or hasRole('INTERNAL')` | *own* |
| VendorController.getVendorBySmartieUserId | GET | `/vendor/get/vendorid/{smartieuserid}` | `hasAuthority('VENDOR:VIEW') or hasRole('INTERNAL')` | *own* |
| VendorTaskController.createVendorTask | POST | `/vendor/create/task` | `hasAuthority('VENDOR_TASK:CREATE')` |  |
| VendorTaskController.updateVendorTask | PUT | `/vendor/update/task` | `hasAuthority('VENDOR_TASK:UPDATE')` |  |
| VendorTaskController.getVendorTaskById | GET | `/vendor/task/{vendortaskid}` | `hasAuthority('VENDOR_TASK:VIEW') or hasRole('INTERNAL')` | *own* candidate-services VendorTaskClient calls /vendor/task |
| VendorTaskController.getVendorTaskByIdExternal | GET | `/vendor/task/{vendortaskid}/external` | `hasAuthority('VENDOR_TASK:VIEW') or hasRole('INTERNAL')` | *confirm* If this is opened from an email link without login, it must be a public path with a signed token instead |
| VendorTaskController.getAllVendorTaskByVendorId | POST | `/vendor/task/list/{vendorid}` | `hasAuthority('VENDOR_TASK:VIEW')` | *own, rows* |
| VendorTaskController.deactivateVendorTask | DELETE | `/vendor/task/deactivate/{vendortaskid}` | `hasAuthority('VENDOR_TASK:DELETE')` |  |
| VendorTaskController.getAllVendorTask | POST | `/vendor/task/search` | `hasAuthority('VENDOR_TASK:VIEW')` | *rows* |
| VendorTaskController.getJobDescriptionByTaskId | GET | `/vendor/task/job/description/{taskid}` | `hasAnyAuthority('VENDOR_TASK:VIEW', 'JOB:VIEW')` | *own* |
| VendorTaskController.getCandidatesByTaskId | GET | `/vendor/task/candidates/{taskid}` | `hasAnyAuthority('VENDOR_TASK:VIEW', 'CANDIDATE_SUBMISSION:VIEW')` | *own* |
| VendorTaskController.saveOrUpdateVendorCost | POST | `/vendor/task/amount` | `hasAuthority('VENDOR_COST:UPDATE')` |  |
| VendorTaskController.getTaskDetailsById | GET | `/vendor/task/detail/{taskid}` | `hasAuthority('VENDOR_TASK:VIEW') or hasRole('INTERNAL')` | *own* Returns the entity: strip cost fields unless VENDOR_COST:VIEW |
| VendorTaskController.getAllVendorTaskByStatus | POST | `/vendor/task/overall/status` | `hasAuthority('VENDOR_TASK:VIEW') or hasRole('INTERNAL')` | *rows* |
| VendorTaskController.updateVendorCost | POST | `/vendor/task/updatecost` | `hasAuthority('VENDOR_COST:UPDATE')` |  |

### notification-services (2)

| Controller.method | HTTP | Path | @PreAuthorize | Notes |
|---|---|---|---|---|
| SendNotificationController.sendSMS | POST | `/sms` | `hasRole('INTERNAL')` | *confirm* Only other services send SMS. Confirm the Angular app never calls it directly |
| SendNotificationController.sendEmail | POST | `/email` | `hasAuthority('NOTIFICATION_TEMPLATE:SEND') or hasRole('INTERNAL')` | *confirm* Ad-hoc templated email from the HR screen needs NOTIFICATION_TEMPLATE:SEND |

### auth-services (40)

Do not enable the shared auto-configuration here (auth-services has its own `SecurityFilterChain`). See section 7.

| Controller.method | HTTP | Path | @PreAuthorize | Notes |
|---|---|---|---|---|
| AuthController.registerUser | POST | `/register` | `permitAll()` |  |
| AuthController.loginUser | POST | `/login` | `permitAll()` |  |
| AuthController.logoutUser | POST | `/logout` | `permitAll()` |  |
| AuthController.verifyUser | POST | `/verify` | `permitAll()` |  |
| AuthController.ad | GET/POST | `/ad` | `permitAll()` | *confirm* Azure AD hand-off. Anyone can call it with any email today - check it verifies the ADEntity row |
| AuthController.validateUser | GET/POST | `/validate` | `permitAll()` |  |
| AuthController.jobReportDownLoad | GET | `/report/download` | `hasAuthority('REPORT:VIEW')` | *confirm* fileName request param |
| AuthController.getAccessToken | GET/POST | `/get/access/token` | `hasRole('INTERNAL')` | *confirm* Unknown caller - confirm who uses it before choosing |
| AuthController.employeeOnboard | POST | `/employee/onboard` | `hasAuthority('USER:MANAGE') or hasRole('INTERNAL')` | *confirm* Creates employee logins - the natural hook for admin-services 'Add user' sync |
| AuthController.downloadExcel | GET | `/report/status/download` | `hasAuthority('REPORT:VIEW')` |  |
| SmartieUserController.getAllHr | GET | `/hr` | `hasAnyAuthority('JOB:VIEW', 'APPLICATION:VIEW', 'USER:VIEW') or hasRole('INTERNAL')` | HR dropdowns |
| SmartieUserController.getAllHrv2 | GET | `/hr/v2` | `hasAnyAuthority('JOB:VIEW', 'APPLICATION:VIEW', 'USER:VIEW') or hasRole('INTERNAL')` |  |
| CampusDetailController.listCampusDetails | GET | `/campus/list` | `hasAnyAuthority('CANDIDATE:CREATE', 'JOB:VIEW')` |  |
| CampusDetailController.uploadCampusDetailFile | POST | `/campus/upload` | `hasAuthority('MASTER_DATA:MANAGE')` |  |
| JobPostingController.getJobDetails | GET | `/jobs/seo/{jobid}` | `permitAll()` | Public careers page proxy |
| JobPostingController.getJobPosting | GET | `/jobs/{jobid}` | `permitAll()` | Public careers page proxy |
| JobPostingController.getJobPostingSearch | POST | `/jobs/search` | `permitAll()` | Public careers page proxy |
| OracleController.updateCandidateStatus | PUT | `/oracle/candidate/status/update` | `hasRole('INTERNAL')` | *confirm* If Oracle HCM calls it from outside, it needs its own credential, not the internal key |
| SmartieProfileController.getProfileById | GET | `/profile/{userid}` | `hasAnyAuthority('CANDIDATE:VIEW', 'CANDIDATE_SELF:VIEW', 'EMPLOYEE_PROFILE:VIEW', 'USER:VIEW') or hasRole('INTERNAL')` | *own* |
| SmartieProfileController.updateProfileById | PUT | `/profile/{userid}` | `hasAnyAuthority('CANDIDATE:UPDATE', 'CANDIDATE_SELF:UPDATE', 'EMPLOYEE_PROFILE:UPDATE')` | *own* |
| SmartieProfileController.deleteProfileById | DELETE | `/profile/{userid}` | `hasAnyAuthority('CANDIDATE:DELETE', 'CANDIDATE_SELF:DELETE')` | *own, confirm* |
| SmartieProfileController.getAllProfiles | GET | `/profile` | `hasAuthority('USER:VIEW')` | Every login with PII. Super Admin only |
| SmartieProfileController.getSmartieUser | POST | `/profile/get/smartieuser` | `hasRole('INTERNAL')` | Unauthenticated user lookup today |
| SmartieProfileController.createVendor | POST | `/profile/create/vendor` | `hasAuthority('VENDOR:CREATE') or hasRole('INTERNAL')` |  |
| SmartieProfileController.getCandidates | POST | `/profile/candidates` | `hasAuthority('CANDIDATE:VIEW') or hasRole('INTERNAL')` | *rows* |
| SmartieProfileController.verifyCountryCode | POST | `/profile/verify/countrycode` | `permitAll()` | Used during registration |
| SmartieProfileController.getEmployees | POST | `/profile/get/employees` | `hasAnyAuthority('PANEL_MEMBER:VIEW', 'USER:VIEW') or hasRole('INTERNAL')` |  |
| SmartieProfileController.getSmartieUsers | POST | `/profile/get/smartie/users` | `hasAuthority('CANDIDATE:VIEW') or hasRole('INTERNAL')` |  |
| SmartieProfileController.uploadCandidateDetails | POST | `/profile/upload` | `hasAuthority('CANDIDATE:CREATE')` |  |
| SmartieProfileController.archiveSmartieUsers | POST | `/profile/archive/smartie/users` | `hasAuthority('CANDIDATE:DELETE') or hasRole('INTERNAL')` |  |
| SmartieProfileController.searchEmployee | GET | `/profile/employee/search` | `hasAnyAuthority('USER:VIEW', 'PANEL_MEMBER:VIEW') or hasRole('INTERNAL')` | Admin 'Add user' and panel roster look-up |
| SmartieProfileController.updateSource | PUT | `/profile/{id}/source` | `hasAuthority('CANDIDATE:UPDATE')` |  |
| InterviewController.getInterviewDetails | POST | `/interview/get/details` | `permitAll()` | *confirm* Walk-in kiosk proxy. Stays public until the kiosk has its own device credential |
| InterviewController.updateInterviewLinkStatus | POST | `/interview/link/status` | `permitAll()` | *confirm* Kiosk |
| InterviewController.startPanel | POST | `/interview/start/panel` | `permitAll()` | *confirm* Kiosk |
| InterviewController.updateInterviewProcessStatus | POST | `/interview/process/status` | `permitAll()` | *confirm* Kiosk |
| InterviewController.getDeviceDetails | GET | `/interview/device/get` | `permitAll()` | *confirm* Kiosk |
| InterviewController.allocateDevice | POST | `/interview/device/allocate` | `permitAll()` | *confirm* Kiosk |
| InterviewController.getAssesmentLink | GET | `/interview/get/assesment/link/{deviceId}` | `permitAll()` | *confirm* Kiosk |
| InterviewController.allocateDeviceV2 | POST | `/interview/allocate/device` | `permitAll()` | *confirm* Kiosk |

## 5. Replacing the userType checks (candidate-services example)

Today (`CandidateController.java:55-61`):

```java
boolean isSelf = candidateid.equals(tokenData.getUserId());
boolean isAdminOrHr = tokenData.getUserType() == UserType.EMPLOYEE_HR_ADMIN || tokenData.getUserType() == UserType.EMPLOYEE_HR;
if (!isSelf && !isAdminOrHr) throw new APIException("FORBIDDEN", "Access Denied ...");
```

With RBAC (same rule, driven by the matrix and data scope instead of the login type):

```java
@GetMapping("/candidates/{candidateid}")
@PreAuthorize("hasAnyAuthority('CANDIDATE:VIEW', 'CANDIDATE_SUMMARY:VIEW', 'CANDIDATE_SELF:VIEW') or hasRole('INTERNAL')")
public Candidate getCandidate(@PathVariable("candidateid") UUID candidateid) {
    Candidate c = candidatesService.getcandidateById(candidateid);
    CurrentUser me = RbacContext.requireUser();
    boolean self = candidateid.toString().equals(me.userId());
    if (!self && !RbacContext.isInternalCall()) {
        AccessEvaluator.Decision d = AccessEvaluator.check(me.access(), "CANDIDATE:VIEW",
                new AccessEvaluator.Target("CANDIDATE", candidateid.toString(), c.getHrId(), Set.of(), c.getLob(), c.getLocation()));
        if (!d.allowed()) throw new APIException("FORBIDDEN", d.reason());
    }
    return c;
}
```

`hrId`, `lob`, `location` are whatever fields the entity uses for owner and placement; ownership without such a
field can not be checked, which is itself a finding for that table.

## 6. New permission codes (admin-services seed changeset `rbac-seed-v2`)

The existing services have objects the access matrix never named. Added to the catalogue, granted by default as
below. **Proposed defaults, need the DEP-S1-04 matrix sign-off** like the rest. Super Admin gets none (no routine
recruiting work, same rule as v1). Change them on the matrix screen, not in SQL.

| Code | Recruiter | Recruitment Manager | TA Head | Vendor |
|---|---|---|---|---|
| VENDOR:VIEW | A | A | A | C (own) |
| VENDOR:CREATE |  | A | A |  |
| VENDOR:UPDATE |  | A | A | C (own) |
| VENDOR:APPROVE |  | A | A |  |
| VENDOR_TASK:VIEW | A | A | A | C (own) |
| VENDOR_TASK:CREATE / UPDATE / DELETE |  | A | A |  |
| VENDOR_COST:VIEW |  | A | A |  |
| VENDOR_COST:UPDATE |  |  | A |  |
| PANEL_MEMBER:VIEW | A | A | A |  |
| PANEL_MEMBER:MANAGE |  | A | A |  |
| DEVICE:VIEW | A | A | A |  |
| DEVICE:MANAGE | A | A | A |  |

Databases that already ran the v1 seed get exactly these 35 grants on the next start; earlier admin changes are
kept (tested on H2 and PostgreSQL: fresh 197 grants, upgrade 162 - 1 removed + 35 = 196).

## 7. auth-services (last)

It must keep login, registration, OTP, AD hand-off, the public job proxy and (for now) the walk-in kiosk proxy
open, so the shared auto-configuration (which backs off when a `SecurityFilterChain` exists) is not used. In
`AuthConfig`:

```java
http.csrf(c -> c.disable())
    .sessionManagement(s -> s.sessionCreationPolicy(SessionCreationPolicy.STATELESS))
    .authorizeHttpRequests(a -> a
        .requestMatchers(PUBLIC_PATHS).permitAll()          // the permitAll() rows in the table
        .anyRequest().authenticated())
    .addFilterBefore(new RbacAuthenticationFilter(jwtSecret, rbacAccessClient, internalApiKey),
                     UsernamePasswordAuthenticationFilter.class);
```

plus `@EnableMethodSecurity`. Three endpoints need an owner decision before this step:
`/get/access/token` (unknown caller), `/oracle/candidate/status/update` (if Oracle calls it from outside, it
needs its own credential) and the kiosk proxies (today anyone on the internet can drive them).

## 8. Things this map can not decide from the docs

Rows tagged *confirm* above, plus:

- The endpoint list comes from the project docs, not from the code. A handler added since then has no row;
  `EndpointSecurityTest` fails on it, which is the safety net.
- Hard deletes (`DELETE /candidates/*`, `/applications/*`, `/jobs/*`, vendor documents) are allowed by permission
  here but should become status changes (audit trail, BRD 4.21).
- `GET` endpoints that change data (`/populatejobs`, `/interview/.../clone`, `/interview/versant/cron`) should
  become POST when they are touched.

