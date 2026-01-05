

# 1. Active Directory Overview

## Concept

Active Directory (AD) is a directory service for Windows networks that enables centralized management of organizational resources—users, computers, groups, network devices, file shares, group policies, and trusts. AD handles authentication and authorization within Windows domains but has become an increasing attack target. Designed for backward-compatibility, many features are not "secure by default" and can be easily misconfigured, allowing attackers to move laterally and vertically within networks.

AD is essentially a large read-only database accessible to all domain users, regardless of privilege level. Any basic user account can enumerate most AD objects, making proper security crucial. Multiple attacks can be executed with just a standard domain account, emphasizing the need for defense-in-depth strategies, careful security planning, AD hardening, network segmentation, and least privilege principles. Despite these challenges, AD makes information easily accessible for administrators and users while being highly scalable, supporting millions of objects per domain and allowing additional domains as organizations grow.

<img width="1026" height="857" alt="image" src="https://github.com/user-attachments/assets/4008e950-3d0e-4f72-b79c-d829e054d369" />



























