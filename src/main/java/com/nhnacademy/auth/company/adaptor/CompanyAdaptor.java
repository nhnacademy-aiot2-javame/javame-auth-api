package com.nhnacademy.auth.company.adaptor;

import com.nhnacademy.auth.company.request.CompanyUpdateEmailRequest;
import com.nhnacademy.auth.company.request.CompanyRegisterRequest;
import com.nhnacademy.auth.company.response.CompanyResponse;
import org.springframework.cloud.openfeign.FeignClient;
import org.springframework.http.ResponseEntity;
import org.springframework.validation.annotation.Validated;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PatchMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.PutMapping;
import org.springframework.web.bind.annotation.RequestBody;

import java.util.List;

@FeignClient(name = "member-api", contextId = "companyClient")
public interface CompanyAdaptor {

    @PostMapping("/companies")
    ResponseEntity<CompanyResponse> registerCompany(@Validated @RequestBody CompanyRegisterRequest request);

    @GetMapping("/companies/{companyDomain}")
    ResponseEntity<CompanyResponse> getCompanyByDomain(@PathVariable String companyDomain);

    @GetMapping("/companies")
    ResponseEntity<List<CompanyResponse>> getAllCompanies();

    @PutMapping("/companies/{companyDomain}/email")
    ResponseEntity<CompanyResponse> updateCompanyEmail(@PathVariable String companyDomain,
                                                        @Validated @RequestBody CompanyUpdateEmailRequest request);

    @PatchMapping("/companies/{companyDomain}/deactivate") // PATCH 사용
    ResponseEntity<Void> deactivateCompany(@PathVariable String companyDomain);

    @PatchMapping("/companies/{companyDomain}/activate") //  PATCH 사용
    ResponseEntity<Void> activateCompany(@PathVariable String companyDomain);

}
