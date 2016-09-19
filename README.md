# BachelorThesis Software
This repository contains a set of tools I used to perform measurements for my bachelor thesis.

# Contents
- 1 - [Building](#1-building)
  - 1.1 - [Building prerequisites](#11-building-prerequisites)
  - 1.2 - [Compiling and running](#12-compiling-and-running)
- 2 - [Licence](#2-licence)
  - 2.1 - [Additional libraries](#21-additional-libraries)

# 1 Building

## 1.1 Building prerequisites

The **CertificateDownloader** and **CertificateTester** tools use the *open-source* **Apache Ant** build tool.


## 1.2 Compiling and running

To build the tools, one can simply run
```
ant
```
in the project root directory, which will produce a `out` folder, containing the compiled tools.

Detailed instructions, diagrams and usage examples can be found in my bachelor thesis [(also included in this repository)](BP_Černáč_Martin_2016.pdf) in section *Appendix A* (pages 59-61).

# 2 Licence
**CertificateDownloader** and **CertificateTester** tools are both licensed under the MIT License.

## 2.1 Additional libraries

This repository also contains additional libraries:
- Google Guava 19.0, Apache License 2.0
- Apache Commons CLI 1.3.1, Apache License 2.0
- JUnit 4.12, Eclipse Public License 1.0
- Hamcrest 1.3, BSD 3-Clause License
- SQLite JDBC 3.8.11.2, Apache License 2.0
