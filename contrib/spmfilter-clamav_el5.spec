Summary: spmfilter clamav plugin 
Name: spmfilter-clamav
Version: 0.1
Release: el5.1
License: LGPL
Group: Development/Libraries
Vendor: spmfilter.org
URL: http://www.spmfilter.org
Requires: spmfilter >= 0.4.0
Requires: glib2 >= 2.12
BuildRequires: cmake >= 2.6
BuildRequires: glib2-devel >= 2.12
BuildRequires: spmfilter >= 0.4.0
Buildroot: %{_tmppath}/%{name}-%{version}-%{release}-root

Source: %{name}-%{version}.tar.gz

%description
Plugin to check mails for viruses with the well-known Clam AntiVirus 
open source toolkit

%prep

%setup -q -n %{name}-%{version}

%build
cmake -DPREFIX=/usr .
make 
  
%install
rm -rf $RPM_BUILD_ROOT
make install DESTDIR=$RPM_BUILD_ROOT

%clean
rm -rf $RPM_BUILD_ROOT

%files
%defattr(-,root,root,-)
%{_libdir}/spmfilter/libclamav*
%{_mandir}/man*/*

%changelog
* Wed Mar 31 2010 Axel Steiner <ast@treibsand.com>
- initial Version
