# 				            **IE CODE**

#  **Docker Security Monitoring in a Distributed File System** 

# Team Number: 2

#                                      **Problem statement:**

# 

# In a file system shared between multiple docker containers, it is difficult to implement role based access for ensuring security if there are a very large number of containers involved. There is a requirement of in depth monitoring of containers and implementation of security rules to ensure proper file operations, namely write, update and delete to ensure data is consistent with respect to roles assigned to host containers. 

# **Proposed solution:**

# We aim to set up a distributed file system with access for all containers. Containers will be able to manipulate or access the files stored in the file system. In depth monitoring of container activity is done to check for system calls made for file operations. Security rules are set up for file access in containers. These security rules will be implemented in real time based on data received from monitoring of the containers. At the end, we aim to integrate the security rules for the containers.

# **Technologies used:**

* Linux (Ubuntu): Operating system  
* GlusterFS: Distributed File System  
* Docker: Containerization  
* Falco: Security Monitoring  
* eBPF (bpftrace, bcc): stopping unauthorized processes  
* Prometheus: Metric scraping  
* Grafana: Creating Dashboards  
* Python, C

**Methodology:**  
 Setting Up the Environment  
Install Linux and required frameworks and dependencies.  
	Learn about file systems and operating systems.  
Learning Phase  
Gain knowledge of Docker, including images, containers, networking, orchestration, and Docker Compose.  
Learn about Falco for file system monitoring and security.  
Explore eBPF and bpftrace for tracing and monitoring system calls.  
Implementation  
Setup a distributed file system and integrate it with Docker for file access by containers.  
Implement basic security rules using Falco to monitor data and prevent unauthorized actions.  
Integrate eBPF with Falco for enhanced monitoring and logging of container activities.  
Testing and Improvement  
Test the system with a large number of containers and improve security rules accordingly.  
Provide a user-friendly dashboard for monitoring and visualization using Grafana.

# **Results:** 

Successful Integration  
Docker containers were successfully integrated with a distributed file system, allowing shared access.  
Monitoring and security rules were effectively implemented using Falco and eBPF  
Enhanced Monitoring  
Improved tracing and monitoring with eBPF and bpftrace, providing detailed logs of system calls.  
Scalability Testing  
Security rules were refined and improved to handle large-scale scenarios with multiple containers.  
Visualization  
	Grafana dashboard provided a comprehensive visualization of monitoring-data, enhancing user accessibility.	    

# **Future work:** 

Improving Security Rules   
Enhance security rules to cover additional edge cases and more complex scenarios.

Real-Time Alerting  
Implement real-time alert systems for suspicious activity detection.

Extending Support for More File Systems  
Expand compatibility with different types of distributed file systems.

Automation  
Automate the deployment process for easier integration in various environments.

Performance Optimization  
	Improve monitoring performance to reduce overhead and increase efficiency.

**Key Learnings:**

Hands-On Experience with Docker, Falco, and eBPF  
Gained practical knowledge in using Docker containers with distributed file systems.  
Understood how to set up Falco for real-time monitoring of system calls.  
	Explored the power of eBPF for detailed tracing and monitoring.

Scalability Considerations  
	Addressing security concerns when scaling to a large number of    containers.  
	  
Visualization Techniques  
	Enhanced visualization through Grafana for monitoring and logging purposes.

Collaboration and Project Management  
	Effective communication and collaboration within a team to achieve project milestones.

**References:**   
Ubuntu setup: [https://www.youtube.com/watch?v=mXyN1aJYefc\&t=347s](https://www.youtube.com/watch?v=mXyN1aJYefc&t=347s)  
Ubuntu docs: [https://help.ubuntu.com/stable/ubuntu-help/index.html](https://help.ubuntu.com/stable/ubuntu-help/index.html)  
Docker Installation: [https://docs.docker.com/engine/install/ubuntu/](https://docs.docker.com/engine/install/ubuntu/)  
GlusterFS Installation: [https://gluster-documentations.readthedocs.io/en/latest/Quick-Start-Guide/Quickstart/](https://gluster-documentations.readthedocs.io/en/latest/Quick-Start-Guide/Quickstart/)  
Falco Docs: [https://falco.org/docs/getting-started/falco-linux-quickstart/](https://falco.org/docs/getting-started/falco-linux-quickstart/)  
bcc Docs: [https://android.googlesource.com/platform/external/bcc/+/refs/heads/android10-c2f2-s1-release/docs](https://android.googlesource.com/platform/external/bcc/+/refs/heads/android10-c2f2-s1-release/docs/reference_guide.md)  
Grafana Docs: [https://grafana.com/docs/grafana-cloud/visualizations/dashboards/build-dashboards/create-dashboard/](https://grafana.com/docs/grafana-cloud/visualizations/dashboards/build-dashboards/create-dashboard/)  
eBPF by Liz Rice: [https://github.com/lizrice/learning-ebpf](https://github.com/lizrice/learning-ebpf)

# **Team Members:**

1. # Prabhav S Korwar

2. # Aashi Kumari

3. # Ahan Halder