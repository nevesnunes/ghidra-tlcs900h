//PCode emulation script that outputs trace logs of TLCS-900/H programs
//@author flib
//@category
//@keybinding
//@menupath
//@toolbar

import java.io.BufferedReader;
import java.io.BufferedWriter;
import java.io.FileWriter;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.nio.file.StandardOpenOption;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.ArrayList;
import java.util.Formatter;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Map.Entry;
import java.util.Set;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import db.Transaction;
import ghidra.app.cmd.disassemble.DisassembleCommand;
import ghidra.app.emulator.EmulatorHelper;
import ghidra.app.plugin.processors.sleigh.SleighLanguage;
import ghidra.app.script.GhidraScript;
import ghidra.framework.store.LockException;
import ghidra.pcode.memstate.MemoryState;
import ghidra.program.database.ProgramDB;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSpace;
import ghidra.program.model.lang.LanguageID;
import ghidra.program.model.lang.OperandType;
import ghidra.program.model.lang.Register;
import ghidra.program.model.listing.CodeUnit;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.Memory;
import ghidra.program.model.mem.MemoryAccessException;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.program.model.mem.MemoryBlockException;
import ghidra.program.model.symbol.RefType;
import ghidra.util.exception.NotFoundException;

public class TLCS900Emu extends GhidraScript {
	/**
	 * When the first 0x1000 bytes of the current program under
	 * analysis match the hash given by the execution, emulation
	 * will start at the entry address, and end either when the 
	 * target address or avoid address was reached.
	 * <p>
	 * Separate trace logs are generated for each execution.
	 */
	private record Execution (Long entry, Long end, Long avoid, String label, String signature) {}
	private static final List<Execution> EXECUTIONS = List.of(
			new Execution(0x200046L, 0x2002e5L, 0xffffffL, "bb", "8b3dd60bdbafaee6278de78524b7f78d3db9a8f3"),
			new Execution(0xff2456L, 0x200046L, 0xffffffL, "bb", "8b3dd60bdbafaee6278de78524b7f78d3db9a8f3"),
			
			new Execution(0x2000e4L, 0x2009caL, 0x2009cfL, "cputest", "017822757efdc5593df00d507624641de65a4ab9"),
			new Execution(0xff27a2L, 0x2000e4L, 0xffffffL, "cputest", "017822757efdc5593df00d507624641de65a4ab9"),

			new Execution(0x200040L, 0x3f1e2cL, 0xffffffL, "sonic" ,"ead2de4f6451a71cc03545a80ea3f89f9f0cbfd5")
	);

	/**
	 * Directory where all state files are placed under.
	 */
	private static final String WORK_DIR = String.format("%s/code/wip/tlcs900h/tmp", System.getProperty("user.home"));

	/**
	 * Labeled interrupts and their handler addresses in both BIOS ROMs. 
	 */
	private static final Map<String, Long> INT_VEC = new HashMap<>();

	/**
	 * Interrupt levels to be set after hardware interrupts are raised.
	 * <p>
	 * Entries are updated at runtime on CPU I/O writes.
	 */
	private static final Map<String, Integer> INT_VEC_LEVELS = new HashMap<>();
	
	/**
	 * CPU I/O registers and bit ranges used to lookup interrupt levels.
	 */
	private record InterruptIO (String label, int start, int end) {}
	private static final Map<Integer, Set<InterruptIO>> INT_VEC_IO_BITS = new HashMap<>();

	static {
		INT_VEC.put("SWI0",   0x00ffff00L);
		INT_VEC.put("SWI1",   0x00ffff04L);
		INT_VEC.put("SWI2",   0x00ffff08L);
		INT_VEC.put("SWI3",   0x00ffff0cL);
		INT_VEC.put("SWI4",   0x00ffff10L);
		INT_VEC.put("SWI5",   0x00ffff14L);
		INT_VEC.put("SWI6",   0x00ffff18L);
		INT_VEC.put("SWI7",   0x00ffff1cL);
		INT_VEC.put("NMI",    0x00ffff20L);
		INT_VEC.put("INTWD",  0x00ffff24L);
		INT_VEC.put("INT0",   0x00ffff28L);
		INT_VEC.put("INT4",   0x00ffff2cL);
		INT_VEC.put("INT5",   0x00ffff30L);
		INT_VEC.put("INT6",   0x00ffff34L);
		INT_VEC.put("INT7",   0x00ffff38L);
		INT_VEC.put("$3C",    0x00ffff3cL);
		INT_VEC.put("INTT0",  0x00ffff40L);
		INT_VEC.put("INTT1",  0x00ffff44L);
		INT_VEC.put("INTT2",  0x00ffff48L);
		INT_VEC.put("INTT3",  0x00ffff4cL);
		INT_VEC.put("INTTR4", 0x00ffff50L);
		INT_VEC.put("INTTR5", 0x00ffff54L);
		INT_VEC.put("INTTR6", 0x00ffff58L);
		INT_VEC.put("INTTR7", 0x00ffff5cL);
		INT_VEC.put("INTRX0", 0x00ffff60L);
		INT_VEC.put("INTTX0", 0x00ffff64L);
		INT_VEC.put("INTRX1", 0x00ffff68L);
		INT_VEC.put("INTTX1", 0x00ffff6cL);
		INT_VEC.put("INTAD",  0x00ffff70L);
		INT_VEC.put("INTTC0", 0x00ffff74L);
		INT_VEC.put("INTTC1", 0x00ffff78L);
		INT_VEC.put("INTTC2", 0x00ffff7cL);
		INT_VEC.put("INTTC3", 0x00ffff80L);

		INT_VEC_LEVELS.put("SWI0", 1);
		INT_VEC_LEVELS.put("SWI1", 2);
		INT_VEC_LEVELS.put("SWI2", 3);
		INT_VEC_LEVELS.put("SWI3", 4);
		INT_VEC_LEVELS.put("SWI4", 5);
		INT_VEC_LEVELS.put("SWI5", 6);
		INT_VEC_LEVELS.put("SWI6", 7);
		INT_VEC_LEVELS.put("INT0", 1);
		INT_VEC_LEVELS.put("INT4", 5);
		INT_VEC_LEVELS.put("INT5", 6);
		INT_VEC_LEVELS.put("INT6", 7);
		
		INT_VEC_IO_BITS.put(0x70, Set.of(new InterruptIO("INT0",   0, 3), new InterruptIO("INTAD",  4, 7)));
		INT_VEC_IO_BITS.put(0x71, Set.of(new InterruptIO("INT4",   0, 3), new InterruptIO("INT5",   4, 7)));
		INT_VEC_IO_BITS.put(0x72, Set.of(new InterruptIO("INT6",   0, 3), new InterruptIO("INT7",   4, 7)));
		INT_VEC_IO_BITS.put(0x73, Set.of(new InterruptIO("INTT0",  0, 3), new InterruptIO("INTT1",  4, 7)));
		INT_VEC_IO_BITS.put(0x74, Set.of(new InterruptIO("INTT2",  0, 3), new InterruptIO("INTT3",  4, 7)));
		INT_VEC_IO_BITS.put(0x75, Set.of(new InterruptIO("INTTR4", 0, 3), new InterruptIO("INTTR5", 4, 7)));
		INT_VEC_IO_BITS.put(0x76, Set.of(new InterruptIO("INTTR6", 0, 3), new InterruptIO("INTTR7", 4, 7)));
		INT_VEC_IO_BITS.put(0x77, Set.of(new InterruptIO("INTRX0", 0, 3), new InterruptIO("INTTX0", 4, 7)));
		INT_VEC_IO_BITS.put(0x78, Set.of(new InterruptIO("INTRX1", 0, 3), new InterruptIO("INTTX1", 4, 7)));
		INT_VEC_IO_BITS.put(0x79, Set.of(new InterruptIO("INTTC0", 0, 3), new InterruptIO("INTTC1", 4, 7)));
		INT_VEC_IO_BITS.put(0x7a, Set.of(new InterruptIO("INTTC2", 0, 3), new InterruptIO("INTTC3", 4, 7)));
	}

	@Override
	protected void run() throws Exception {
		byte[] code = new byte[0x1000];
		currentProgram.getMemory().getBytes(addr(0x200000), code);

		EXECUTIONS.forEach(exec -> {
			try {
				if (isRomLoaded(code, exec.signature())) {
					runAt(exec);
				} else {
					printerr(String.format("Skipped execution '%s' (did not match loaded ROM)", exec.label()));
				}
			} catch (Exception e) {
				throw new RuntimeException(e);
			}
		});
	}

	private void runAt(Execution execution) throws Exception {
		Long entry = execution.entry();
		Map<Long, String> ints = new HashMap<>();
		Map<Long, String> io = new HashMap<>();
		setupHardwareEvents(entry, ints, io);

		setupMem(entry);

		// TODO: Verify Z80 emulation
		Map<Long, String> apuIO = new HashMap<>();
		EmulatorHelper apu = setupCoprocessor(entry, apuIO);
		
		EmulatorHelper cpu = new EmulatorHelper(currentProgram);
		cpu.setBreakpoint(addr(execution.end()));
		cpu.setBreakpoint(addr(execution.avoid()));

		setupRegs(cpu, entry);

		long line_i = 1;
		Path outFile = Paths.get(String.format("%s/0x%08x.%s.emu.log", System.getProperty("user.home"), entry, execution.label()));
		Files.write(outFile , new byte[0], StandardOpenOption.CREATE, StandardOpenOption.TRUNCATE_EXISTING);
		FileWriter fw = new FileWriter(outFile.toString(), true);
		try (BufferedWriter bw = new BufferedWriter(fw)) {
			while (!monitor.isCancelled()) {
				List<String> handledEvents = new ArrayList<>();
				String event = null;
				do {
					event = handleHardwareEvent(cpu, ints, io, apuIO, line_i);
					if (event != null) {
						handledEvents.add(event);
						line_i++; // Skip over non-instruction line
						if (line_i % 100000 == 0) {
							println(String.format("Passed line=%d", line_i));
						}
					}
				} while (event != null);
				
				for (String handledEvent : handledEvents) {
					bw.write(handledEvent);
				}

				lookaheadHardwareIOReads(cpu, io, apuIO, line_i);

				Map<Long, Long> refs = extractRefs(cpu);
				String line = dump(cpu);
				
				boolean ok = cpu.step(monitor);
				if (!ok) {
					printerr(cpu.getLastError());
					break;
				}
				line_i++;
				if (line_i % 100000 == 0) {
					println(String.format("Passed line=%d", line_i));
				}

				StringBuilder context = new StringBuilder();
				for (Entry<Long, Long> refEntry : refs.entrySet()) {
					long ref = refEntry.getKey();
					long refOldVal = refEntry.getValue();
					long refNewVal = load32(ref, cpu);
					context.append(context.isEmpty() ? " [" : ", ");
					if (refOldVal != refNewVal) {
						context.append(String.format("%08x: %08x -> %08x", ref, refOldVal, refNewVal));
					} else {
						context.append(String.format("%08x: %08x", ref, refOldVal));
					}
				}
				if (!context.isEmpty()) {
					line += context.append("]").toString();
				}
				line += "\n";
				bw.write(line);

				if (cpu.getExecutionAddress().equals(addr(execution.end()))) {
					break;
				}
				if (cpu.getExecutionAddress().equals(addr(execution.avoid()))) {
					throw new RuntimeException(String.format("Reached address to avoid @ 0x%08x!", execution.avoid()));
				}
			}
		} finally {
			apu.dispose();
			cpu.dispose();
		}
	}

	private void setupMem(long entry)
			throws IOException, LockException, MemoryBlockException, NotFoundException, MemoryAccessException {
		// Copy I/O, CPU, APU, and Video RAM
		Path memFile = Paths.get(String.format("%s/0x%08x.mem", WORK_DIR, entry));
		byte[] memBytes = Files.readAllBytes(memFile);
		for (MemoryBlock mb : currentProgram.getMemory().getBlocks()) {
			if (!mb.isInitialized()) {
				currentProgram.getMemory().convertToInitialized(mb, (byte) '\0');
			}
		}
		currentProgram.getMemory().setBytes(addr(0), memBytes, 0, 0xC000);

		// High flash ROM addresses are commonly written to during BIOS initialization routines,
		// and later on by program code (e.g. to erase previous contents after reset). 
		// We copy those changes but avoid overwriting already disassembled code / data.
		memFile = Paths.get(String.format("%s/0x%08x.mem_0x280000", WORK_DIR, entry));
		memBytes = Files.readAllBytes(memFile);
		for (int i = 0x280000; i < 0x3fffff; i++) {
			Address addr_i = addr(i);
			if (currentProgram.getListing().getUndefinedDataAt(addr_i) != null) {
				currentProgram.getMemory().setByte(addr_i, memBytes[i - 0x280000]);
			}
		}
	}

	private void setupRegs(EmulatorHelper emu, long entry) throws IOException {
		Map<String, Long> regs = new HashMap<>();
		Path regsFile = Paths.get(String.format("%s/0x%08x.reg", WORK_DIR, entry));
		if (!Files.exists(regsFile)) {
			printerr(String.format("Register defaults will be loaded, state file does not exist: %s", regsFile));

			regs.put("XWA_0", 0x00000000L);
			regs.put("XBC_0", 0x00000000L);
			regs.put("XDE_0", 0x00000000L);
			regs.put("XHL_0", 0x00000000L);
			regs.put("XWA_1", 0x00000000L);
			regs.put("XBC_1", 0x00000000L);
			regs.put("XDE_1", 0x00000000L);
			regs.put("XHL_1", 0x00000000L);
			regs.put("XWA_2", 0x00000000L);
			regs.put("XBC_2", 0x00000000L);
			regs.put("XDE_2", 0x00000000L);
			regs.put("XHL_2", 0x00000000L);
			regs.put("XWA_3", 0x00000000L);
			regs.put("XBC_3", 0x00000000L);
			regs.put("XDE_3", 0x00000000L);
			regs.put("XHL_3", 0x00000000L);
			regs.put("XIX",   0x00000000L);
			regs.put("XIY",   0x00000000L);
			regs.put("XIZ",   0x00000000L);
			regs.put("XSP",   0x00006c00L);
			regs.put("SR",    0x0000f800L); // 0b0111_1000_0000_0000 = SYSM IFF MAX RFP szhvnc
			regs.put("PC",    entry);
		} else {
			try (BufferedReader reader = Files.newBufferedReader(regsFile, StandardCharsets.UTF_8)) {
				String line;
				while ((line = reader.readLine()) != null) {
					String[] vars = line.split(":");
					regs.put(vars[0].strip(), Long.parseLong(vars[1].strip(), 16));
				}
			}
		}

		try {
			List.of(
					"XWA_0", "XBC_0", "XDE_0", "XHL_0",
					"XWA_1", "XBC_1", "XDE_1", "XHL_1",
					"XWA_2", "XBC_2", "XDE_2", "XHL_2",
					"XWA_3", "XBC_3", "XDE_3", "XHL_3",
					"XIX", "XIY", "XIZ", "XSP", "SR", "PC"
			).forEach(reg -> emu.writeRegister(reg, regs.get(reg)));

			// Copy banked values to current register bank
			long rfp = (emu.readRegister("SR").longValue() & 0b0000_0111_0000_0000) >> 8;
			if (rfp == 0) {
			    emu.writeRegister("XWA", emu.readRegister("XWA_0").longValue());
			    emu.writeRegister("XBC", emu.readRegister("XBC_0").longValue());
			    emu.writeRegister("XDE", emu.readRegister("XDE_0").longValue());
			    emu.writeRegister("XHL", emu.readRegister("XHL_0").longValue());
			} else if (rfp == 1) {
			    emu.writeRegister("XWA", emu.readRegister("XWA_1").longValue());
			    emu.writeRegister("XBC", emu.readRegister("XBC_1").longValue());
			    emu.writeRegister("XDE", emu.readRegister("XDE_1").longValue());
			    emu.writeRegister("XHL", emu.readRegister("XHL_1").longValue());
			} else if (rfp == 2) {
			    emu.writeRegister("XWA", emu.readRegister("XWA_2").longValue());
			    emu.writeRegister("XBC", emu.readRegister("XBC_2").longValue());
			    emu.writeRegister("XDE", emu.readRegister("XDE_2").longValue());
			    emu.writeRegister("XHL", emu.readRegister("XHL_2").longValue());
			} else if (rfp == 3) {
			    emu.writeRegister("XWA", emu.readRegister("XWA_3").longValue());
			    emu.writeRegister("XBC", emu.readRegister("XBC_3").longValue());
			    emu.writeRegister("XDE", emu.readRegister("XDE_3").longValue());
			    emu.writeRegister("XHL", emu.readRegister("XHL_3").longValue());
			}
		} catch (Exception e) {
			throw new RuntimeException(e);
		}
	}

	private EmulatorHelper setupCoprocessor(long cpuEntry, Map<Long, String> apuIO) throws Exception {
		// TODO: Z80 instructions are bundled with I/O, effectively ignored
		parseHardwareEvents(cpuEntry, "%s/0x%08x.apu", apuIO);
		parseHardwareEvents(cpuEntry, "%s/0x%08x.apu.io", apuIO);
		
		SleighLanguage language = (SleighLanguage) getLanguage(new LanguageID("z80:LE:16:default"));
		Program program = new ProgramDB("bios_z80", language, language.getDefaultCompilerSpec(), this);

		byte[] code = new byte[0x1000];
		currentProgram.getMemory().getBytes(addr(0xff0000), code);
		try (Transaction tx = program.openTransaction("Init")) {
			AddressSpace space = program.getAddressFactory().getDefaultAddressSpace();
			Address entry = space.getAddress(0);
			Memory mem = program.getMemory();
			mem.createInitializedBlock(".text", entry, 0x1000, (byte) 0, monitor, false);
			mem.setBytes(entry, code);
			mem.getBlock(addr(0)).setPermissions(true, false, true);
		}
		
		EmulatorHelper apu = new EmulatorHelper(program);
		
		return apu;
	}

	private void setupHardwareEvents(long entry, Map<Long, String> ints, Map<Long, String> io) throws IOException {
		parseHardwareEvents(entry, "%s/0x%08x.int", ints);
		parseHardwareEvents(entry, "%s/0x%08x.io", io);
	}

	private void parseHardwareEvents(long entry, String filename, Map<Long, String> state) throws IOException {
		Path path = Paths.get(String.format(filename, WORK_DIR, entry));
		if (!Files.exists(path)) {
			printerr(String.format("Events will be ignored, state file does not exist: %s", path));
			return;
		}

		try (BufferedReader reader = Files.newBufferedReader(path, StandardCharsets.UTF_8)) {
			String line;
			while ((line = reader.readLine()) != null) {
				String[] vars = line.split(",");
				StringBuilder sb = new StringBuilder();
				for (int i = 1; i < vars.length; i++) {
					sb.append(sb.isEmpty() ? "" : ",");
					sb.append(i == vars.length - 1 ? vars[i].stripTrailing() : vars[i]);
				}
				state.put(Long.parseLong(vars[0].strip()), sb.toString());
			}
		}
	}

	private String handleHardwareEvent(EmulatorHelper emu,
			Map<Long, String> ints,
			Map<Long, String> io,
			Map<Long, String> apuIO,
			long ins_i) {
		String handledInt = handleHardwareInt(emu, ints, ins_i);
		if (handledInt != null) {
			return handledInt;
		}
		
		String handledIO = handleHardwareIO(emu, io, ins_i);
		if (handledIO != null) {
			return handledIO;
		}
		
		String handledApuIO = handleHardwareCoprocessorIO(emu, apuIO, ins_i);
		if (handledApuIO != null) {
			return handledApuIO;
		}
		
		return null;
	}

	/**
	 * Updates registers and stack, as described in User Manual "3.3.1 General-Purpose Interrupt Processing"
	 */
	private String handleHardwareInt(EmulatorHelper emu, Map<Long, String> ints, long ins_i) {
		if (ints.containsKey(ins_i)) {
			if (!INT_VEC.containsKey(ints.get(ins_i))) {
				throw new RuntimeException(String.format("Unknown interrupt: 0x%08x", ints.get(ins_i)));
			}

			final long sp = emu.readRegister("XSP").longValue();
			final long pc = emu.readRegister("PC").longValue();
			final long sr = emu.readRegister("SR").longValue();
			emu.writeMemoryValue(addr(sp - 4), 4, pc);
			emu.writeMemoryValue(addr(sp - 6), 2, sr & 0xffff);

			final long intVecEntry = INT_VEC.get(ints.get(ins_i));
			final long intVecHandler = unpack32(emu.readMemory(addr(intVecEntry), 4));
			emu.writeRegister(emu.getStackPointerRegister(), sp - 6);
			emu.writeRegister(emu.getPCRegister(), intVecHandler);

			final long iff = INT_VEC_LEVELS.getOrDefault(ints.get(ins_i), 7);
			emu.writeRegister(emu.getProgram().getRegister("SR"), (sr & 0b1000_1111_1111_1111) | (iff << 12));

			return String.format("CPU Interrupt (%s) @ line=%d [PC: %08x, SR: %04x, XSP: %08x %08x] -> [%08x] = %08x\n",
					ints.get(ins_i),
					ins_i,
					pc,
					sr & 0xffff,
					load32(sp - 6, emu),
					load32(sp - 2, emu),
					intVecEntry,
					intVecHandler);
		}

		return null;
	}

	/**
	 * Interrupt level parsing, as described in:
	 * - TMP95C061F Manual "3.8 8-bit Timers", e.g. registers set to generate timer 1 interrupt
	 * - https://github.com/ares-emulator/ares/blob/3d3838d8b41a6ce3e54782fe5f22aeb79f5cd609/ares/ngp/cpu/io.cpp#L688
	 */
	private String handleHardwareIO(EmulatorHelper emu, Map<Long, String> io, long ins_i) {
		// TODO: More events need to be logged and handled, such as:
		// - Flash commands;
		// - Video RAM reads;
		Pattern p = Pattern.compile("write *([0-9a-f]+) = ([0-9a-f]+)");
		String context = io.get(ins_i);
		if (io.containsKey(ins_i)) {
			Matcher m = p.matcher(io.get(ins_i));
			if (m.find()) {
				int ioAddr = Integer.parseInt(m.group(1), 16);
				int ioVal = Integer.parseInt(m.group(2), 16);
				if (INT_VEC_IO_BITS.containsKey(ioAddr)) {
					for (InterruptIO iio : INT_VEC_IO_BITS.get(ioAddr)) {
						int level = ((ioVal & (0b111 << iio.start())) >> iio.start()) & 0b111;
						INT_VEC_LEVELS.put(iio.label(), level + 1);
						context = String.format("%s, %s->%d", context, iio.label(), level + 1);
					}
				}
			}
			return String.format("CPU I/O @ line=%d [%s]\n", ins_i, context);
		}
		
		return null;
	}
	
	/**
	 * Copies APU writes to equivalent CPU address range.
	 */
	private String handleHardwareCoprocessorIO(EmulatorHelper emu, Map<Long, String> apuIO, long ins_i) {
		Pattern p = Pattern.compile("write *([0-9a-f]+) = ([0-9a-f]+)");
		if (apuIO.containsKey(ins_i)) {
			Matcher m = p.matcher(apuIO.get(ins_i));
			if (m.find()) {
				long ioAddr = Long.parseLong(m.group(1), 16);
				long ioVal = Long.parseLong(m.group(2), 16);
				if (ioAddr > 0x1000) {
					printerr(String.format("APU I/O @ line=%d has OOB(?) addr=%04x\n", ins_i, ioAddr));
				} else {
					emu.writeMemoryValue(addr(0x007000L + ioAddr), 1, ioVal);
				}
				return String.format("APU I/O @ line=%d [%s]\n", ins_i, apuIO.get(ins_i));
			}
			
			return String.format("APU @ line=%d\n", ins_i);
		}
		
		return null;
	}

	/**
	 * At runtime, several I/O addresses are accessed. In our trace logs,
	 * I/O reads happen after an instruction was decoded and logged.
	 * To avoid implementing I/O update logic, we can lookahead to parse these reads
	 * and update our emulated memory, so that when we step into an instruction,
	 * it will read those expected values.
	 */
	private void lookaheadHardwareIOReads(EmulatorHelper emu, Map<Long, String> io, Map<Long, String> apuIO, long ins_i) {
		Pattern p = Pattern.compile("read *([0-9a-f]+) = ([0-9a-f]+)");
		long lookahead_i = ins_i;
		while (true) {
			lookahead_i++;
			if (apuIO.containsKey(lookahead_i)) {
				continue;
			}
			if (io.containsKey(lookahead_i)) {
				Matcher m = p.matcher(io.get(lookahead_i));
				if (m.find()) {
					long ioReg = Long.parseLong(m.group(1), 16);
					long ioVal = Long.parseLong(m.group(2), 16);
					emu.writeMemoryValue(addr(ioReg), 1, ioVal);
				} else {
					break;
				}
			} else {
				break;
			}
		}
	}

	/**
	 * Checks if the given instruction either manipulates the stack or accesses memory addresses,
	 * so that these can be added as context to our trace logs.
	 */
	private Map<Long, Long> extractRefs(EmulatorHelper emu) {
		Map<Long, Long> refs = new HashMap<>();

		Address addr = emu.getExecutionAddress();
		Instruction ins = explore(emu, addr);

		if (ins.getMnemonicString().equalsIgnoreCase("ret")
				|| ins.getMnemonicString().equalsIgnoreCase("reti")
				|| ins.getFlowType().equals(RefType.CALL_TERMINATOR)
				|| ins.getFlowType().equals(RefType.CONDITIONAL_CALL_TERMINATOR)) {
			long sp = emu.readRegister("XSP").longValue();
			refs.put(sp, load32(sp, emu));
			refs.put(sp + 4, load32(sp + 4, emu));
			return refs;
		}

		for (int i = 0; i < ins.getNumOperands(); i++) {
			Long ref = null;
			if (OperandType.isAddress(ins.getOperandType(i))) {
				ref = Long.parseLong(ins.getAddress(i).toString(), 16);
			}
			else if (OperandType.isDynamic(ins.getOperandType(i))) {
				for(Object obj : ins.getDefaultOperandRepresentationList(i)) {
					if (obj instanceof Register) {
						Register reg = (Register) obj;
						ref = emu.getEmulator().getMemState().getValue(reg);
					}
				}
			}

			if (ref != null) {
				refs.put(ref, load32(ref, emu));
			}
		}

		return refs;
	}

	/**
	 * Retrieves an instruction at the given address, considering cases where
	 * it may not have been previously explored during auto-analysis.
	 */
	private Instruction explore(EmulatorHelper emu, Address addr) {
		Instruction ins = currentProgram.getListing().getInstructionAt(addr);
		if (ins == null) {
			// Valid but unexplored code
			if (currentProgram.getListing().getUndefinedDataAt(addr) != null) {
				DisassembleCommand cmd = new DisassembleCommand(addr, null, true);
				if (!cmd.applyTo(emu.getProgram()) || cmd.getDisassembledAddressSet().isEmpty()) {
					// Workaround for data auto-analysis creating false positive references
					// in the middle of unexplored code
					int i = 1;
					while (i < 20) {
						Address nextAddr = addr(addr.getUnsignedOffset() + i);
						if (currentProgram.getListing().getInstructionAt(nextAddr) != null) {
							break;
						}
						if (currentProgram.getListing().getDefinedDataAt(nextAddr) != null) {
							currentProgram.getListing().clearCodeUnits(addr, nextAddr, false);
						}
						i++;
					}

					cmd = new DisassembleCommand(addr, null, true);
					if (!cmd.applyTo(emu.getProgram()) || cmd.getDisassembledAddressSet().isEmpty()) {
						throw new RuntimeException(String.format("Null instruction @ 0x%08x", addr.getUnsignedOffset()));	
					}
				}
				ins = currentProgram.getListing().getInstructionAt(addr);
				if (ins == null) {
					throw new RuntimeException(String.format("Null instruction after disasm @ 0x%08x", addr.getUnsignedOffset()));
				}
			} else {
				throw new RuntimeException(String.format("Jumped to data @ 0x%08x", addr.getUnsignedOffset()));
			}
		}
		
		return ins;
	}
	
	//
	// Helper methods
	//

	private boolean isRomLoaded(byte[] code, String executionHash) throws NoSuchAlgorithmException {
		byte[] hash = MessageDigest.getInstance("SHA-1").digest(code);
	    try (Formatter formatter = new Formatter()) {
			for (byte b : hash) {
			    formatter.format("%02x", b);
			}
			return formatter.toString().equalsIgnoreCase(executionHash);
		}
	}

	private Address addr(long offset) {
		return currentProgram.getAddressFactory().getDefaultAddressSpace().getAddress(offset);
	}

	private long unpack32(byte[] mem) {
		return ((mem[3] & 0xff) << 24) 
				| ((mem[2] & 0xff) << 16) 
				| ((mem[1] & 0xff) << 8) 
				| ((mem[0] & 0xff));
	}

	private long load32(Long ref, EmulatorHelper emu) {
		MemoryState memState = emu.getEmulator().getMemState();
		AddressSpace addressSpace = addr(ref).getAddressSpace();

		// MemoryState will apply endian-aware packing,
		// but we just want to look at memory bytes as-is,
		// hence peeking one byte at a time.
		return (memState.getValue(addressSpace, ref, 1) << 24)
				| (memState.getValue(addressSpace, ref + 1, 1) << 16)
				| (memState.getValue(addressSpace, ref + 2, 1) << 8)
				| (memState.getValue(addressSpace, ref + 3, 1));
	}

	private String dump(EmulatorHelper emu) {
		long pc = emu.readRegister("PC").longValue();
		CodeUnit cu = currentProgram.getListing().getCodeUnitAt(addr(pc));
		StringBuilder sb = new StringBuilder();
		sb.append(String.format("%08x %-32s", pc, cu));
		sb.append(String.format("XWA:%08x ", emu.readRegister("XWA").longValue()));
		sb.append(String.format("XBC:%08x ", emu.readRegister("XBC").longValue()));
		sb.append(String.format("XDE:%08x ", emu.readRegister("XDE").longValue()));
		sb.append(String.format("XHL:%08x ", emu.readRegister("XHL").longValue()));
		sb.append(String.format("XIX:%08x ", emu.readRegister("XIX").longValue()));
		sb.append(String.format("XIY:%08x ", emu.readRegister("XIY").longValue()));
		sb.append(String.format("XIZ:%08x ", emu.readRegister("XIZ").longValue()));
		sb.append(String.format("XSP:%08x ", emu.readRegister("XSP").longValue()));

		long sr = emu.readRegister("SR").longValue();
		sb.append(String.format("IFF:%d ", (sr & 0b0111_0000_0000_0000) >> 12));
		sb.append(String.format("RFP:%d ", (sr & 0b0000_0111_0000_0000) >> 8));
		sb.append((sr & 0b0000_0000_1000_0000) != 0 ? "S" : "s");
		sb.append((sr & 0b0000_0000_0100_0000) != 0 ? "Z" : "z");
		sb.append((sr & 0b0000_0000_0001_0000) != 0 ? "H" : "h");
		sb.append((sr & 0b0000_0000_0000_0100) != 0 ? "V" : "v");
		sb.append((sr & 0b0000_0000_0000_0010) != 0 ? "N" : "n");
		sb.append((sr & 0b0000_0000_0000_0001) != 0 ? "C" : "c");

		return sb.toString();
	}
}
