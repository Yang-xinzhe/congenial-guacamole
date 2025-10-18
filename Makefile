# Main Makefile for ARM32 Instruction Analysis Toolkit

.PHONY: all clean install help
.PHONY: screening extraction analysis
.PHONY: fast-filter timeout-filter register-analysis pmu-analysis

# Default target
all: screening extraction analysis

# Main categories
screening:
	@echo "Building instruction screening tools..."
	$(MAKE) -C 1-instruction-screening/fast-filter
	$(MAKE) -C 1-instruction-screening/timeout-filter

extraction:
	@echo "Building result extraction tools..."
	$(MAKE) -C 2-result-extraction

analysis:
	@echo "Building instruction analysis tools..."
	$(MAKE) -C 3-instruction-analysis/register-analysis
	$(MAKE) -C 3-instruction-analysis/pmu-analysis

# Individual components
fast-filter:
	$(MAKE) -C 1-instruction-screening/fast-filter

timeout-filter:
	$(MAKE) -C 1-instruction-screening/timeout-filter

register-analysis:
	$(MAKE) -C 3-instruction-analysis/register-analysis

pmu-analysis:
	$(MAKE) -C 3-instruction-analysis/pmu-analysis

# Clean all
clean:
	@echo "Cleaning all build artifacts..."
	$(MAKE) -C 1-instruction-screening/fast-filter clean
	$(MAKE) -C 1-instruction-screening/timeout-filter clean
	$(MAKE) -C 2-result-extraction clean
	$(MAKE) -C 3-instruction-analysis/register-analysis clean
	$(MAKE) -C 3-instruction-analysis/pmu-analysis clean

# Debug builds
debug:
	@echo "Building debug versions..."
	$(MAKE) -C 1-instruction-screening/fast-filter debug
	$(MAKE) -C 1-instruction-screening/timeout-filter debug
	$(MAKE) -C 2-result-extraction debug
	$(MAKE) -C 3-instruction-analysis/register-analysis debug
	$(MAKE) -C 3-instruction-analysis/pmu-analysis debug

# Install (with warnings about cross-compilation)
install:
	@echo "Installing extraction tools (x86 host)..."
	$(MAKE) -C 2-result-extraction install
	@echo ""
	@echo "WARNING: ARM32 binaries need to be copied to ARM target system:"
	@echo "  - 1-instruction-screening/fast-filter/{ins_check,inst_testframe}"
	@echo "  - 1-instruction-screening/timeout-filter/{dispatcher,single_check}"
	@echo "  - 3-instruction-analysis/register-analysis/{reg_compare,macro_analyzer}"
	@echo "  - 3-instruction-analysis/pmu-analysis/pmu_test"

# Help
help:
	@echo "ARM32 Instruction Analysis Toolkit Build System"
	@echo ""
	@echo "Available targets:"
	@echo "  all              - Build all components"
	@echo "  screening        - Build instruction screening tools (ARM32)"
	@echo "  extraction       - Build result extraction tools (x86)"
	@echo "  analysis         - Build instruction analysis tools (ARM32)"
	@echo ""
	@echo "Individual components:"
	@echo "  fast-filter      - Build fast instruction filter (ARM32)"
	@echo "  timeout-filter   - Build timeout-based filter (ARM32)"
	@echo "  register-analysis- Build register analysis tools (ARM32)"
	@echo "  pmu-analysis     - Build PMU analysis tools (ARM32)"
	@echo ""
	@echo "Other targets:"
	@echo "  clean            - Clean all build artifacts"
	@echo "  debug            - Build debug versions"
	@echo "  install          - Install tools (x86 only, ARM32 needs manual copy)"
	@echo "  help             - Show this help message"
	@echo ""
	@echo "Requirements:"
	@echo "  - arm-linux-gnueabihf-gcc for ARM32 targets"
	@echo "  - gcc for x86 host tools" 