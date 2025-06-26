### **Title Page**

* Title: **Porting the Volatility2 Procdump Plugin to Volatility3**
* Author: Gillian MASSE
* Course: Digital Forensics
* Institution: EURECOM

### **1. Introduction**

* Context: memory forensics, Volatility framework, and plugin ecosystem.
* Motivation for porting: Volatility 2 deprecated, Volatility 3 is now standard.
* Objective: port the `procdump` plugin and extract PE binaries from memory.
* Target memory image: OtterCTF.vmem (Windows 7 x64).

---

### **2. Background**

#### 2.1. Volatility 2 vs Volatility 3

* Differences in architecture: object model, configuration, and plugin design.
* Plugin API evolution: from procedural to class-based.

#### 2.2. The Procdump Plugin

* Purpose: extract process executable code from memory.
* How it worked in Volatility 2.
* Challenge: plugin not available in Volatility 3.

---

### **3. Methodology**

#### 3.1. Initial Setup

* Environment: Ubuntu + Python virtualenv.
* Installation of Volatility 3, dependencies, loading test image.

#### 3.2. First Attempts and Errors

* Attempt to directly run Vol2 plugin: failed.
* Creation of a basic plugin skeleton.
* Common errors encountered:

  * `KeyError: 'nt_symbols'`
  * `AttributeError: 'SymbolSpace' object has no attribute 'get_symbols'`
  * `InvalidAddressException`
  * PE headers not found or inaccessible
  * `TypeError: wrong type for PID`

#### 3.3. Troubleshooting Strategy

* Consulted documentation, official issues, community posts.
* Analyzed structure of similar plugins (`vadinfo`, `dumpfiles`, `malfind`).
* Learned how symbol resolution and kernel modules are configured in Vol3.

---

### **4. Final Implementation**

#### 4.1. Design Choices

* Based on `pslist` and `vadinfo` usage of `kernel` module.
* Integration of CLI arguments for output folder and PID filtering.
* Dumping via VAD regions instead of relying on base address.

#### 4.2. Plugin Functionality

* Lists processes and extracts memory regions with valid MZ headers.
* Saves as `.dmp` files in a chosen folder.
* Handles inaccessible memory and exceptions gracefully.

#### 4.3. Output Organization

* Automatic classification of dumped files.
* Usage of `file` and `strings` commands to verify dump validity.
* Optional post-processing script to sort files by type.

---

### **5. Evaluation**

* ✅ Successfully extracted executables (e.g., `explorer.exe`, `BitTorrent.exe`).
* 🧪 Compared against `vadump`, `psscan`, and manual strings analysis.

* ❌ Known limitations:
  * Dumping non-contiguous memory
  * Handling packed or obfuscated PE files

---

### **6. Conclusion**

* Summary of challenges and achievements.
* Value of porting deprecated plugins.
* Reflection on skills learned (plugin architecture, debugging, Windows internals).
* Ideas for future work (e.g., add yara scanning or hash computation).

---

### **7. Appendices**

* 📎 Appendix A: Full source code of the plugin
* 📎 Appendix B: Example outputs and screenshots
* 📎 Appendix C: Dump classification script
* 📎 Appendix D: Log of key errors and fixes (timeline)

---

Souhaites-tu que je te rédige maintenant une première section du rapport en anglais (par exemple l’introduction) ?









### 1. Introduction

Memory forensics has become a crucial field in cybersecurity and digital investigations, enabling analysts to inspect volatile memory (RAM) for traces of malware, active processes, hidden artifacts, and injected code. A key tool in this domain is the Volatility Framework, a popular open-source memory analysis platform that allows the parsing and extraction of valuable runtime information from memory snapshots.

The Volatility ecosystem has undergone a major transition with the deprecation of Volatility 2. As Python 2.x became obsolete and modern environments moved towards Python 3.x and 64-bit architectures, the community shifted focus to Volatility 3. This newer version offers a modular, object-oriented design and enhanced support for modern operating systems. However, this migration came at the cost of losing access to many existing plugins that were never ported from Volatility 2 to Volatility 3.

One of the critical plugins missing in Volatility 3 is `procdump`. Originally designed for Volatility 2, this plugin allowed investigators to dump executable images of running processes from memory. Such functionality is essential when analyzing malware, reverse engineering packed binaries, or preserving forensic artifacts for further examination.

The objective of this project is to re-implement the `procdump` plugin for Volatility 3. This includes creating a new plugin compatible with the updated framework, which will iterate through process memory, identify executable regions, and save them as Portable Executable (PE) files. The target memory sample used for this development and testing is `OtterCTF.vmem`, a 64-bit Windows 7 memory image commonly used for training and CTF challenges.

This report outlines the full porting process, including the technical challenges encountered, the methodological solutions explored, and the final implementation results.


### 2. Background

#### 2.1. Volatility 2 vs Volatility 3

**Architectural Differences**
Volatility 2 and Volatility 3 differ significantly in their core design. Volatility 2 was built around a monolithic structure where plugins directly interacted with memory layers and types. In contrast, Volatility 3 adopts a modular and object-oriented design, emphasizing separation of concerns and extensibility. It introduces better abstraction layers, support for multiple platforms, and a cleaner API.

**Configuration and Symbol Handling**
In Volatility 2, symbols and kernel structures were hardcoded or manually defined through profiles. Volatility 3 leverages ISF (Intermediate Symbol Format) files and dynamically loads kernel symbols via the `kernel` module. This allows for more accurate and flexible parsing of operating system internals.

**Plugin API Evolution**
The plugin system has evolved from procedural scripting in Volatility 2 to class-based interfaces in Volatility 3. Each plugin now inherits from `PluginInterface`, defines `get_requirements()` for CLI parameters, and uses `run()` to output data in a structured format like `TreeGrid`. This change improves maintainability and enforces a standard plugin lifecycle.

These changes require plugin developers to rewrite Volatility 2 code using the new interfaces and conventions introduced in Volatility 3, ensuring compatibility with the latest framework features and standards.


#### 2.2 The Procdump Plugin

The original purpose of the `procdump` plugin in Volatility 2 was to extract in-memory executable files associated with running processes. It scanned the virtual address space of each process to locate the PE (Portable Executable) headers and dump the corresponding code segments to disk. This was particularly useful in malware investigations where analysts needed to recover unpacked or injected code from memory-resident processes.

In Volatility 2, the plugin used direct access to the memory layers and process structures to identify valid image bases, verify the presence of an `MZ` header, and dump a fixed-size segment of memory as a file. Its implementation was mostly procedural, heavily reliant on the now outdated plugin and memory access APIs. Despite its simplicity, it was effective in many investigative scenarios.

One of the primary challenges addressed in this project was the fact that the `procdump` plugin had not been ported to Volatility 3. Due to the extensive architectural changes between Volatility 2 and 3, the original code could not be reused as-is. Instead, a full reimplementation was required, leveraging the class-based structure of Volatility 3, the `PluginInterface` inheritance model, the `TreeGrid` rendering output, and the improved handling of symbol spaces and memory access.

Rebuilding this plugin thus required both a deep understanding of Volatility 3's plugin architecture and a practical strategy for traversing process memory spaces. This included integrating symbol resolution, managing invalid memory access gracefully, and dumping relevant virtual address descriptors (VADs) into individual files, all while maintaining compatibility with standard Volatility 3 practices.


### 3. Methodology

#### 3.1. Initial Setup

The initial setup of the project began with preparing an appropriate working environment for plugin development and testing. A Linux-based system (Ubuntu) was chosen due to its compatibility with Python tooling and ease of using command-line forensic tools. To isolate dependencies and ensure a controlled environment, a dedicated Python virtual environment was created. This allowed for the installation of Volatility 3 and its specific dependencies without interfering with system-wide Python packages.

Once the virtual environment was ready, the latest version of the Volatility 3 framework was cloned from its official GitHub repository. Dependencies such as `capstone`, `pycryptodome`, and other Python packages required for memory parsing and binary analysis were installed using `pip`. After ensuring that the framework could run basic plugins on example images, the target memory image `OtterCTF.vmem`—a Windows 7 x64 snapshot—was placed in the working directory for analysis.

With the test image in place, initial commands such as `windows.pslist` and `windows.info` were executed to confirm that the image was correctly parsed and that the required kernel symbols could be resolved. This step validated that the setup was correctly configured and ready for plugin development and debugging.


#### 3.2 First Attempts and Errors

Porting the `procdump` plugin from Volatility 2 to Volatility 3 turned out to be significantly more challenging than initially anticipated. The early development phase was characterized by repeated failures, a fragmented understanding of the new architecture, and a wide array of cryptic error messages that required extensive investigation.

The **first approach** was to naively attempt running the original Volatility 2 plugin within the Volatility 3 environment. As expected, this failed entirely. Volatility 3's architecture is class-based, rendering Volatility 2's procedural plugins obsolete. Furthermore, the transition from a flat memory model to a layered architecture with symbol resolution introduced additional incompatibilities that rendered direct reuse of code ineffective.

A minimal plugin skeleton was built from scratch, extending Volatility 3’s `PluginInterface` class. It defined the required kernel module, as well as custom parameters like `--dump-dir` and `--pid`. However, even this basic structure was met with immediate runtime errors.

One of the **first major issues** was the notorious `KeyError: 'nt_symbols'`. This occurred while attempting to retrieve symbols from the kernel without properly resolving the kernel module. Unlike Volatility 2 where symbol resolution was handled more implicitly, Volatility 3 requires explicitly referencing the module name provided by the `self.config['kernel']` configuration key. The resolution was to dynamically fetch the kernel object and update all references accordingly.

Another frequent issue was `AttributeError: 'SymbolSpace' object has no attribute 'get_symbols'`. This stemmed from misunderstandings of how symbol handling works in Volatility 3, where lower-level symbol access is abstracted away. The fix involved abandoning Vol2-style accessors and relying instead on documented usage in official Volatility 3 plugins like `pslist` and `vadinfo`.

Attempts to extract executables using the `ImageBaseAddress` field from the `PEB` of a process often led to `InvalidAddressException` errors. These exceptions occurred when the memory address in question was either unmapped or inaccessible. To address this, the implementation strategy shifted towards traversing Virtual Address Descriptors (VADs), ensuring that memory segments dumped were valid and accessible.

Another persistent challenge was a `TypeError` triggered during rendering: “wrong type for PID”. This arose when the PID, expected as a `format_hints.Hex` object, was passed as a raw integer or worse, as `None`. The solution was to sanitize the output by wrapping each PID in the proper rendering object before including it in the final TreeGrid.

In some cases, the plugin would dump memory segments that did not contain recognizable PE headers (i.e., no `MZ` signature). This suggested the dumps were either corrupted or not PE files at all. However, using Unix tools like `file` and `strings`, it was discovered that many of these files were valid PE fragments, merely not aligned at the beginning of the executable code. This insight led to better filtering mechanisms during the dump process.

Each of these failures—while initially frustrating—contributed to a deeper understanding of Volatility 3's architecture. The repeated cycle of trial, error, debugging, and refactoring played a key role in shaping a functional, robust plugin that conformed to the framework's expectations. The experience highlighted the importance of reading the source code of official plugins, using meaningful logging for diagnostics, and validating assumptions against known working examples.


#### 3.3 Troubleshooting Strategy

Overcoming the initial roadblocks required a methodical and research-driven troubleshooting strategy. Recognizing that the Volatility 3 ecosystem was significantly different from its predecessor, the first step was to **consult a wide range of resources**. These included the official Volatility 3 documentation, GitHub issues posted by other users encountering similar problems, detailed plugin implementation examples provided within the framework, and several online discussions from forums such as Stack Overflow and GitHub Discussions.

A key insight from this phase was the value of examining **existing and well-maintained plugins** that already functioned under the Volatility 3 architecture. Notably, plugins like `vadinfo`, `dumpfiles`, and `malfind` were analyzed in depth. These plugins demonstrated best practices in memory access, error handling, and symbol resolution, serving as crucial templates for the development of the new `procdump` port. By dissecting how these plugins invoked kernel modules and traversed virtual memory, it became possible to align our plugin’s architecture with the expectations of the Volatility 3 engine.

One particularly important lesson was the difference in **symbol resolution**. Volatility 3 enforces a stricter relationship between the symbol tables and memory layers. Unlike Volatility 2, where symbols like `_EPROCESS` could be referenced more loosely, Volatility 3 requires that all such references be mapped explicitly to a `context.modules[...]` object derived from the configuration. This understanding helped eliminate the `KeyError: 'nt_symbols'` and other related issues.

During the debugging process, **incremental testing and verbose logging** were adopted as core practices. Instead of attempting to implement large blocks of logic at once, functionality was added step-by-step, with print statements and exception handling blocks used to verify assumptions at each stage. This made it easier to isolate problems and understand exactly which operations were failing and why.

Finally, the use of Unix utilities such as `file`, `strings`, and `xxd` proved indispensable for **verifying dump integrity**. These tools helped confirm that the dumped files were indeed valid PE binaries or data segments, even when the Volatility plugin itself returned ambiguous or failed results. This multi-tool validation approach ensured that the plugin’s output was not only syntactically correct but also forensically meaningful.

Overall, the troubleshooting strategy emphasized **careful code analysis, community knowledge, modular development**, and consistent testing. These practices transformed an initially dysfunctional prototype into a working and reliable plugin aligned with Volatility 3's design principles.


### **4. Final Implementation**


#### 4.1 Design Choices

The design of the final implementation drew heavily from the architecture and best practices of existing Volatility 3 plugins such as `pslist` and `vadinfo`. A key early decision was to respect Volatility 3's plugin structure by extending the `PluginInterface` class, thereby ensuring compatibility with the framework's execution model, configuration system, and renderer.

One of the most significant design choices was to avoid relying on the process's `PEB.ImageBaseAddress`, as initially attempted. Accessing this base address was consistently unreliable across processes, often triggering `InvalidAddressException` errors. Instead, the plugin was restructured to traverse the process's VAD (Virtual Address Descriptor) tree using the `get_vad_root()` method. This approach allowed the plugin to locate and dump every valid memory segment mapped into a process, significantly improving both reliability and coverage.

To enhance usability, two configuration parameters were integrated using Volatility's `requirements` system:

* `--dump-dir`: a required argument specifying the destination folder for dumped files.
* `--pid`: an optional argument allowing users to restrict the operation to specific process IDs.

The inclusion of these parameters made the plugin suitable for both broad memory surveys and targeted analysis. Furthermore, the plugin's output was constructed using Volatility's `TreeGrid` rendering system, with consistent formatting of `PID` values as hexadecimal and clear logging of results (e.g., dump location or encountered error).

The dumping logic was encapsulated within a `try/except` block to ensure graceful handling of inaccessible memory regions or unknown exceptions. Each VAD was checked for read access, and segments were only dumped if they could be successfully read. The resulting files were named using the convention: `ImageName_PID_StartAddr-EndAddr.dmp`, providing a meaningful and traceable identifier for each memory region extracted.

Overall, these design choices collectively ensured that the plugin was robust, user-configurable, and aligned with the operational philosophy of Volatility 3. The shift to VAD-based dumping was particularly impactful, offering a significant improvement over legacy techniques based on fixed base addresses.

#### 4.2. Plugin Functionality

The final version of the `ProcdumpCustom` plugin was designed to replicate and modernize the behavior of the original Volatility 2 `procdump` plugin, while leveraging the capabilities and structure of the Volatility 3 framework.

The plugin begins by **enumerating all active processes** using the `pslist` module, which is a reliable and standard way to retrieve the process list via the Windows kernel module provided in the configuration. Once the relevant processes are identified, the plugin uses an optional PID filter to target only specific processes as specified by the user. This allows precise targeting and avoids unnecessary dumping of irrelevant memory segments.

For each selected process, the plugin then attempts to traverse its **Virtual Address Descriptor (VAD) tree**, which represents the structure of allocated memory regions. This traversal ensures a more comprehensive and realistic view of memory, compared to relying solely on the `ImageBaseAddress` from the process's PEB, which often fails in Volatility 3 due to permission or mapping issues.

During the traversal, each VAD region is read from memory and **dumped into a `.dmp` file**. The filename includes the process name, its PID, and the memory range of the region, helping analysts understand the origin and scope of the memory segment.

To ensure that the dumped memory contains potentially valid executable data, the plugin performs a lightweight check for the **"MZ" signature** at the beginning of the memory content, which indicates a valid Portable Executable (PE) header. Although not a guarantee of full integrity, this heuristic greatly reduces the number of unusable dumps.

The plugin is also **robust in handling errors and exceptions**. If a memory region is inaccessible due to invalid addresses or insufficient privileges, it catches the exception and logs a descriptive error message in the output. This ensures that the entire plugin doesn't fail because of one bad region and provides useful diagnostic information to the user.

As a result, the final plugin behaves in a predictable, transparent, and user-friendly way, mirroring the intent of the original `procdump` while adapting it to the new Volatility 3 standards.



#### 4.3. Output Organization

* Automatic classification of dumped files.
* Usage of `file` and `strings` commands to verify dump validity.
* Optional post-processing script to sort files by type.

---

### 5. Evaluation

The plugin was tested on a real Windows 7 memory dump obtained from the OtterCTF challenge. The results confirmed the expected behavior: processes were correctly identified, and executable memory regions were extracted with valid `MZ` headers.

Successfully extracted executable files such as `explorer.exe`, `BitTorrent.exe`, and various DLLs. Each dump was verified using Unix tools like `file` and `strings`, and their format confirmed to be PE32+.

Results were cross-checked against other Volatility 3 plugins like `vadinfo`, `psscan`, and `dumpfiles`. Manual validation showed high consistency between the regions dumped and the executable memory space of the related processes. While the plugin did not replicate every aspect of the original Volatility 2 `procdump`, it fulfilled its core purpose: locating and saving valid PE segments.

#### Known Limitations

 The plugin currently exhibits a few important limitations:

* **Dumping non-contiguous memory**: VAD traversal ensures memory segments are valid, but executables split across disjoint regions are not reassembled. This may result in partially usable executables.
* **Handling packed or obfuscated PE files**: The plugin does not include detection mechanisms for compressed, encrypted, or packed binaries. Such executables may appear malformed after extraction.
* **Memory padding**: Dumps are written as raw memory with optional zero-padding. This can confuse automated PE parsers expecting structured alignment.

Future improvements could target these gaps by incorporating PE reconstruction, entropy analysis, or optional YARA-based validation.

### 6. Conclusion

Porting the `procdump` plugin from Volatility 2 to Volatility 3 was both a technically demanding and enriching experience. The journey involved navigating a modernized plugin framework, confronting architectural changes, and overcoming numerous implementation roadblocks. Initial expectations for a straightforward translation quickly gave way to a deeper exploration of Volatility 3's plugin system, memory model, and debugging mechanics.

One of the key accomplishments was adapting the plugin to Volatility 3's layered architecture. This required an in-depth understanding of how memory layers, symbol spaces, and virtual address descriptors (VADs) interact. Instead of relying on the `PEB.ImageBaseAddress` as in Volatility 2, the Volatility 3 implementation smartly traverses VADs to identify and extract memory regions, ensuring higher compatibility and reliability.

The project also highlighted the enduring value of maintaining and modernizing deprecated tools. Despite the lack of official Volatility 3 support for many plugins, reverse engineering and adapting legacy code extends the utility of memory forensic investigations. This is especially important in scenarios where quick adaptation is necessary to deal with specific malware or forensic targets.

From a skills perspective, the work provided hands-on experience in Python debugging, class-based plugin design, exception handling, and Windows memory internals. It also emphasized the importance of iterative testing, source-level reading of framework code, and using diagnostic tools like `file` and `strings` to validate results.

Future improvements could enhance the plugin by integrating YARA-based signature scanning, reconstructing fragmented PE files, or calculating hash values for each dump to assist in malware classification.

Overall, this project not only achieved its primary goal of restoring `procdump` functionality to Volatility 3, but also provided a valuable deep dive into forensic tooling and memory analysis techniques.



