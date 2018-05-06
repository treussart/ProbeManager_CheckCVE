**************************
CheckCVE for Probe Manager
**************************


|Licence| |Version|


.. image:: https://api.codacy.com/project/badge/Grade/64dc0388b44a4b75952d2b6ad3920c0c?branch=master
   :alt: Codacy Badge
   :target: https://www.codacy.com/app/treussart/ProbeManager_CheckCVE?utm_source=github.com&amp;utm_medium=referral&amp;utm_content=treussart/ProbeManager_CheckCVE&amp;utm_campaign=Badge_Grade

.. image:: https://api.codacy.com/project/badge/Coverage/64dc0388b44a4b75952d2b6ad3920c0c?branch=master
   :alt: Codacy Coverage
   :target: https://www.codacy.com/app/treussart/ProbeManager_CheckCVE?utm_source=github.com&amp;utm_medium=referral&amp;utm_content=treussart/ProbeManager_CheckCVE&amp;utm_campaign=Badge_Coverage

.. |Licence| image:: https://img.shields.io/github/license/treussart/ProbeManager_CheckCVE.svg
.. |Version| image:: https://img.shields.io/github/tag/treussart/ProbeManager_CheckCVE.svg


Presentation
============

Module to check the CVE of softwares


Features
--------

* Check if there is a CVE for a software on a remote server.

Installation
============

Install with `ProbeManager <https://github.com/treussart/ProbeManager/>`_

Usage
=====

Administration Page of the module :
-----------------------------------

.. image:: https://raw.githubusercontent.com/treussart/ProbeManager_CheckCVE/master/data/admin-index.png
  :align: center
  :width: 80%

Page to add an instance which verifies the CVE of the software of a remote server :
-----------------------------------------------------------------------------------

.. image:: https://raw.githubusercontent.com/treussart/ProbeManager_CheckCVE/master/data/admin-checkcve-add.png
  :align: center
  :width: 80%

* Give a unique name for this instance, example: server-proxy_checkcve.
* Give a crontab for planning verifications of existing CVE.
* Specify the server on which the software to be monitored is located.
* Select the software to be monitored.
* Select a whitelist for which the software are not vulnerable.

Page to add a software for which a check of CVE can be made :
-------------------------------------------------------------

.. image:: https://raw.githubusercontent.com/treussart/ProbeManager_CheckCVE/master/data/admin-software-add.png
  :align: center
  :width: 70%

* Give the name of the software as seen by the OS. example: dovecot-imapd is the name of Dovecot on Debian.
* Specify for which operating systems the software is installed.
* Give its valid `CPE <https://nvd.nist.gov/products/cpe>`_ name.
* Specify how it was installed, by which package manager.

Page of an instance :
---------------------

.. image:: https://raw.githubusercontent.com/treussart/ProbeManager_CheckCVE/master/data/instance-index.png
  :align: center
  :width: 80%

* The button 'Check CVE': launch a CVE audit, check if there are known vulnerabilities on this instance.
* Under CVE found: There are links for CVE found. For Debian, it redirects to the security bug tracker. For others, it redirects to www.cvedetails.com.

Miscellaneous
-------------

CVEs are registered with their `CVE ID <https://cve.mitre.org/about/faqs.html#what_is_cve_id>`_, example : CVE-2016-6304

Before putting a CVE in a whitelist, it is necessary to make sure that the patch is well applied to its version.
There are sites that help you know this,for example for Debian : `Security Bug Tracker <https://security-tracker.debian.org/tracker/>`_

On the home page, if the instance icon is red, there are known vulnerabilities on this instance. If the icon is green, there are none.

All operating systems that have an SSH server are theoretically compatible, in fact as currently only the APT and Brew package manager are supported, this limits to Debian, Ubuntu and OSX.
