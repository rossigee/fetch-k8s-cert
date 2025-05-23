Name:          fetch-k8s-cert
Version:       1.3.2
Release:       1%{?dist}
Summary:       Tool to retrieve x509 TLS certificates from a K8S cluster.
License:       Public domain
 
URL:           https://github.com/rossigee/fetch-k8s-cert
Source0:       https://github.com/rossigee/fetch-k8s-cert/releases/download/v%{version}/%{name}-%{version}.tar.bz2
 
#BuildRequires: bash
 
%description
%{name} is a tool to retrieve X509 TLS certs from a K8S cluster. Typically, these certs are managed as Secrets by 'cert-manager'.
 
 
%prep
%setup -q
 
%build
# TODO?
 
%files
%doc README.md
%license LICENSE
%{_bindir}/%{name}
usr/lib/systemd/system/fetch-k8s-cert.service
usr/lib/systemd/system/fetch-k8s-cert.timer
