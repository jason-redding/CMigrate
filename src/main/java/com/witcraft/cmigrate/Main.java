package com.witcraft.cmigrate;

import java.io.Console;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardCopyOption;
import java.security.Key;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.UnrecoverableKeyException;
import java.security.cert.Certificate;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateException;
import java.security.cert.CertificateExpiredException;
import java.security.cert.CertificateNotYetValidException;
import java.security.cert.X509Certificate;
import java.text.SimpleDateFormat;
import java.util.Arrays;
import java.util.Collection;
import java.util.Date;
import java.util.Enumeration;
import java.util.HashMap;
import java.util.function.BiConsumer;
import java.util.logging.Level;
import java.util.logging.Logger;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import java.util.regex.PatternSyntaxException;
import org.apache.commons.cli.CommandLine;
import org.apache.commons.cli.DefaultParser;
import org.apache.commons.cli.HelpFormatter;
import org.apache.commons.cli.MissingArgumentException;
import org.apache.commons.cli.MissingOptionException;
import org.apache.commons.cli.Option;
import org.apache.commons.cli.Options;
import org.apache.commons.cli.ParseException;

/**
 *
 * @author Jason Redding
 */
public class Main {

	private static final Console console;
	private static final Option OPTION_INCLUDE_INVALID_CERTIFICATES = Option.builder("x").longOpt("include-invalid").desc("Do not skip invalid certificates.\nDefault is to skip invalid certificates.").build();
	private static final Option OPTION_SOURCE_FILE = Option.builder("f").longOpt("from").required().hasArg().argName("srcfile").desc("The source file from which to copy certificates that aren't found in <destfile>.").build();
	private static final Option OPTION_DESTINATION_FILE = Option.builder("t").longOpt("to").required().hasArg().argName("destfile").desc("The destination file to where certificates are copied.").build();
	private static final Option OPTION_SOURCE_FILE_PASSWORD = Option.builder("p").longOpt("frompass").hasArg().argName("srcpass").desc("The source file password.").build();
	private static final Option OPTION_DESTINATION_FILE_PASSWORD = Option.builder("w").longOpt("topass").hasArg().argName("destpass").desc("The destination file password.").build();
	private static final Option OPTION_ALIAS = Option.builder("a").longOpt("alias").hasArg().argName("pattern").desc("The Regular Expression used to match against alias names.").build();
	private static final Option OPTION_LIST = Option.builder("l").longOpt("list").hasArg(false).desc("List certificates in <srcfile> that are not in <destfile>.").build();
	private static final Options OPTIONS = new Options()
		.addOption(OPTION_INCLUDE_INVALID_CERTIFICATES)
		.addOption(OPTION_SOURCE_FILE)
		.addOption(OPTION_DESTINATION_FILE)
		.addOption(OPTION_SOURCE_FILE_PASSWORD)
		.addOption(OPTION_DESTINATION_FILE_PASSWORD)
		.addOption(OPTION_ALIAS)
		.addOption(OPTION_LIST);
	private static final char[] HEXDIGITS = "0123456789abcdef".toCharArray();
	private final SimpleDateFormat sdf;
//	private MessageDigest sha1;
	private MessageDigest sha512;
	private final CommandLine cli;
	private HashMap<String, KeyStoreEntry> srcHashes;
	private HashMap<String, KeyStoreEntry> destHashes;
	private final Pattern aliasPattern;

	static {
		console = System.console();
	}

	private static CommandLine parseCommandLineArguments(String[] args) throws ParseException {
		try {
			return new DefaultParser().parse(OPTIONS, args, true);
		} catch (MissingOptionException ex) {
			throw new JMissingOptionException(OPTIONS, ex);
		} catch (MissingArgumentException ex) {
			throw new JMissingArgumentException(ex);
		} catch (ParseException ex) {
			throw ex;
		}
	}

	public static void main(String[] args) {
		Exception exception = null;
		try {
			CommandLine cli = parseCommandLineArguments(args);
			Main main = new Main(cli);
			main.readAllKeyStores();
			HashMap<String, KeyStoreEntry> toCopy = main.findDifference();
			boolean listMode = cli.hasOption(OPTION_LIST.getOpt());
			if (!toCopy.isEmpty()) {
				toCopy.forEach(new BiConsumer<String, KeyStoreEntry>() {
					@Override
					public void accept(String alias, KeyStoreEntry entry) {
						if (entry.isX509Certificate()) {
							X509Certificate x509Certificate = entry.getX509Certificate();
							String subjectDN = x509Certificate.getSubjectDN().toString();
							if (!listMode) {
								System.out.format("Adding certificate [%s] as \"%s\"\n", subjectDN, alias);
							} else {
								System.out.format("KeyStore Alias: %s\n    Subject DN: %s\n", alias, subjectDN);
							}
						} else {
							if (!listMode) {
								System.out.format("Adding certificate as \"%s\"\n", alias);
							} else {
								System.out.format("KeyStore Alias: %s\n", alias);
							}
						}
					}
				});
				if (!listMode) {
					try {
						main.writeKeystore(OPTION_DESTINATION_FILE, OPTION_DESTINATION_FILE_PASSWORD, toCopy);
						System.out.println("Done.");
					} catch (Exception ex) {
						Logger.getLogger(Main.class.getName()).log(Level.SEVERE, ex.getMessage(), ex);
					}
				}
			} else {
				if (!listMode) {
					System.out.println("Nothing to do.");
				}
			}
		} catch (Exception ex) {
			exception = ex;
		}
		if (exception != null) {
			Logger.getLogger(Main.class.getName()).log(Level.SEVERE, exception.getMessage(), exception);
			HelpFormatter help = new HelpFormatter();
			help.printHelp("java -jar CMigrate.jar", OPTIONS, true);
		}
	}

	private Main(CommandLine cli) throws ParseException, IOException {
		this.cli = cli;
		Pattern precompiledPattern;
		try {
			precompiledPattern = Pattern.compile(cli.getOptionValue(OPTION_ALIAS.getOpt(), ".*"));
		} catch (PatternSyntaxException ex) {
			Logger.getLogger(Main.class.getName()).log(Level.SEVERE, null, ex);
			precompiledPattern = Pattern.compile(".*");
		}
		this.aliasPattern = precompiledPattern;
		File srcKeystore = new File(cli.getOptionValue(OPTION_SOURCE_FILE.getOpt()));
		File destKeystore = new File(cli.getOptionValue(OPTION_DESTINATION_FILE.getOpt()));
		if (!srcKeystore.exists()) {
			String srcKeystorePath = srcKeystore.getCanonicalPath();
			throw new FileNotFoundException("Source file does not exist: " + srcKeystorePath);
		}
		if (!destKeystore.exists()) {
			String destKeystorePath = destKeystore.getCanonicalPath();
			throw new FileNotFoundException("Destination file does not exist: " + destKeystorePath);
		}
//		System.out.println("\nCongratulations! You provided all required options/arguments.");
		this.sdf = new SimpleDateFormat("yyyy-MM-dd'T'HH-mm-ss-S");
		try {
			sha512 = MessageDigest.getInstance("SHA-512");
		} catch (NoSuchAlgorithmException ex) {
			Logger.getLogger(Main.class.getName()).log(Level.SEVERE, null, ex);
		}
	}

	private HashMap<String, KeyStoreEntry> findDifference() throws NoSuchAlgorithmException {
		boolean includeInvalid = cli.hasOption(OPTION_INCLUDE_INVALID_CERTIFICATES.getOpt());
		boolean hasAliasPattern = cli.hasOption(OPTION_ALIAS.getOpt());
		boolean listMode = cli.hasOption(OPTION_LIST.getOpt());
		HashMap<String, KeyStoreEntry> aliases = new HashMap<>();
		srcHashes.forEach(new BiConsumer<String, KeyStoreEntry>() {
			private final Matcher aliasMatcher = aliasPattern.matcher("");

			@Override
			public void accept(String hash, KeyStoreEntry srcEntry) {
				boolean keepGoing;
				if (!destHashes.containsKey(hash)) {
					if (!includeInvalid) {
						keepGoing = false;
						if (srcEntry.isX509Certificate()) {
							String dn = null;
							try {
								X509Certificate x509Certificate = srcEntry.getX509Certificate();
								dn = x509Certificate.getSubjectDN().toString();
								x509Certificate.checkValidity();
								keepGoing = true;
							} catch (CertificateExpiredException | CertificateNotYetValidException ex) {
								if (dn != null) {
									System.err.format("Skipping invalid alias \"%s\" [%s] %s\n", srcEntry.getAlias(), ex.getMessage(), dn);
								}
							}
						}
					} else {
						keepGoing = true;
					}
					if (keepGoing && hasAliasPattern) {
						aliasMatcher.reset(srcEntry.getAlias());
						if (!aliasMatcher.matches()) {
							keepGoing = false;
							System.err.format("Skipping alias \"%s\" [PatternMismatch: \"%s\"]\n", srcEntry.getAlias(), aliasPattern.pattern());
						} else {
							System.out.format("Alias \"%s\" matches pattern \"%s\"\n", srcEntry.getAlias(), aliasPattern.pattern());
						}
					}
					if (keepGoing) {
						aliases.put(srcEntry.getAlias(), srcEntry);
					}
				}
			}
		});
		return aliases;
	}

	private void readAllKeyStores() {
		readSrcKeystore();
		readDestKeystore();
	}

	private void readSrcKeystore() {
		Option fileOption = OPTION_SOURCE_FILE;
		try {
			readKeystore(fileOption, OPTION_SOURCE_FILE_PASSWORD, srcHashes = new HashMap<>());
		} catch (KeyStoreException | NoSuchAlgorithmException | CertificateException | IOException ex) {
			Logger.getLogger(Main.class.getName()).log(Level.SEVERE, "Failed to load source KeyStore [" + cli.getOptionValue(fileOption.getOpt()) + "]", ex);
		}
	}

	private void readDestKeystore() {
		Option fileOption = OPTION_DESTINATION_FILE;
		try {
			readKeystore(fileOption, OPTION_DESTINATION_FILE_PASSWORD, destHashes = new HashMap<>());
		} catch (KeyStoreException | NoSuchAlgorithmException | CertificateException | IOException ex) {
			Logger.getLogger(Main.class.getName()).log(Level.SEVERE, "Failed to load destination KeyStore [" + cli.getOptionValue(fileOption.getOpt()) + "]", ex);
		}
	}

	private void writeKeystore(Option keystoreOption, Option passOption, HashMap<String, KeyStoreEntry> map) throws KeyStoreException, IOException, NoSuchAlgorithmException, CertificateException {
		writeKeystore(keystoreOption, passOption, map.values());
	}

	private void writeKeystore(Option keystoreOption, Option passOption, Collection<KeyStoreEntry> entries) throws KeyStoreException, IOException, NoSuchAlgorithmException, CertificateException {
		File keystoreFile = new File(cli.getOptionValue(keystoreOption.getOpt()));
		String keystoreFilePath = getFilePath(keystoreFile);
		String defaultKeystoreType = KeyStore.getDefaultType();
		KeyStore keystore = KeyStore.getInstance(defaultKeystoreType);
		String keystoreTargetType;
		if (OPTION_SOURCE_FILE.getOpt().equals(keystoreOption.getOpt())) {
			keystoreTargetType = "source";
		} else {
			keystoreTargetType = "destination";
		}
		char[] ksPassword;
		boolean triedDefaultPassword = false;
		PasswordType pwAttemptType = null;
		IOException wrongPasswordException = null;
		while (true) {
			if (wrongPasswordException == null) {
				if (cli.hasOption(passOption.getOpt())) {
					pwAttemptType = PasswordType.ARGUMENT;
					ksPassword = cli.getOptionValue(passOption.getOpt()).toCharArray();
				} else if (!triedDefaultPassword) {
					pwAttemptType = PasswordType.DEFAULT;
					ksPassword = new char[] {'c', 'h', 'a', 'n', 'g', 'e', 'i', 't'};
				} else if (console != null) {
					pwAttemptType = PasswordType.CONSOLE;
					ksPassword = console.readPassword("Enter password for %s KeyStore [%s]: ", keystoreTargetType, keystoreFilePath);
				} else {
					pwAttemptType = PasswordType.LAST_RESORT;
					ksPassword = new char[] {'c', 'h', 'a', 'n', 'g', 'e', 'i', 't'};
				}
			} else {
				if (console != null) {
					ksPassword = console.readPassword("Incorrect password!\nEnter password for %s KeyStore [%s]: ", keystoreTargetType, keystoreFilePath);
				} else {
					throw wrongPasswordException;
				}
			}
			try (FileInputStream fis = new FileInputStream(keystoreFile)) {
				keystore.load(fis, ksPassword);
			} catch (IOException ex) {
				Throwable cause = ex.getCause();
				if (cause != null && cause instanceof UnrecoverableKeyException) {
					if (PasswordType.DEFAULT.equals(pwAttemptType)) {
						triedDefaultPassword = true;
						continue;
					}
					wrongPasswordException = ex;
					continue;
				}
				throw ex;
			}
			break;
		}
		for (KeyStoreEntry entry : entries) {
			if (entry.isCertificateEntry()) {
				keystore.setCertificateEntry(entry.getAlias(), entry.getCertificate());
			}
		}
		Path keystorePath = keystoreFile.toPath();
		Path outKeystorePath = keystoreFile.toPath();
		try {
			// rename to become backup copy
			Files.move(keystorePath, keystorePath.resolveSibling(keystorePath.getFileName().toString() + ".backup"), StandardCopyOption.ATOMIC_MOVE);
		} catch (Exception ex) {
			String now;
			synchronized (sdf) {
				now = sdf.format(new Date());
			}
			outKeystorePath = keystorePath.resolveSibling(keystorePath.getFileName().toString() + "." + now + ".backup");
			Logger.getLogger(Main.class.getName()).log(Level.SEVERE, null, ex);
		}
		System.out.format("Writing KeyStore [%s]...\n", getFilePath(outKeystorePath.toFile()));
		triedDefaultPassword = false;
		pwAttemptType = null;
		while (true) {
			if (wrongPasswordException == null) {
				if (cli.hasOption(passOption.getOpt())) {
					pwAttemptType = PasswordType.ARGUMENT;
					ksPassword = cli.getOptionValue(passOption.getOpt()).toCharArray();
				} else if (ksPassword != null && ksPassword.length > 0) {
					
				} else if (!triedDefaultPassword) {
					pwAttemptType = PasswordType.DEFAULT;
					ksPassword = new char[] {'c', 'h', 'a', 'n', 'g', 'e', 'i', 't'};
				} else if (console != null) {
					pwAttemptType = PasswordType.CONSOLE;
					ksPassword = console.readPassword("Enter password for %s KeyStore [%s]: ", keystoreTargetType, keystoreFilePath);
				} else {
					pwAttemptType = PasswordType.LAST_RESORT;
					ksPassword = new char[] {'c', 'h', 'a', 'n', 'g', 'e', 'i', 't'};
				}
			} else {
				if (console != null) {
					ksPassword = console.readPassword("Incorrect password!\nEnter password for %s KeyStore [%s]: ", keystoreTargetType, keystoreFilePath);
				} else {
					throw wrongPasswordException;
				}
			}
			try (FileOutputStream fos = new FileOutputStream(outKeystorePath.toFile())) {
				keystore.store(fos, ksPassword);
			} catch (IOException ex) {
				Throwable cause = ex.getCause();
				if (cause != null && cause instanceof UnrecoverableKeyException) {
					if (PasswordType.DEFAULT.equals(pwAttemptType)) {
						triedDefaultPassword = true;
						continue;
					}
					wrongPasswordException = ex;
					continue;
				}
				throw ex;
			} finally {
				if (ksPassword != null && ksPassword.length > 0) {
					Arrays.fill(ksPassword, ' ');
				}
			}
			break;
		}
	}

	private HashMap<String, KeyStoreEntry> readKeystore(Option keystoreOption, Option passOption, HashMap<String, KeyStoreEntry> byHash) throws KeyStoreException, IOException, NoSuchAlgorithmException, CertificateException {
		File keystoreFile = new File(cli.getOptionValue(keystoreOption.getOpt()));
		String keystoreFilePath = getFilePath(keystoreFile);
		String defaultKeystoreType = KeyStore.getDefaultType();
		KeyStore keystore = KeyStore.getInstance(defaultKeystoreType);
		if (byHash == null) {
			byHash = new HashMap<>();
		}
		String keystoreTargetType;
		if (OPTION_SOURCE_FILE.getOpt().equals(keystoreOption.getOpt())) {
			keystoreTargetType = "source";
		} else {
			keystoreTargetType = "destination";
		}
		char[] ksPassword;
		boolean triedDefaultPassword = false;
		PasswordType pwAttemptType = null;
		IOException wrongPasswordException = null;
		while (true) {
			if (wrongPasswordException == null) {
				if (cli.hasOption(passOption.getOpt())) {
					pwAttemptType = PasswordType.ARGUMENT;
					ksPassword = cli.getOptionValue(passOption.getOpt()).toCharArray();
				} else if (!triedDefaultPassword) {
					pwAttemptType = PasswordType.DEFAULT;
					ksPassword = new char[] {'c', 'h', 'a', 'n', 'g', 'e', 'i', 't'};
				} else if (console != null) {
					pwAttemptType = PasswordType.CONSOLE;
					ksPassword = console.readPassword("Enter password for %s KeyStore [%s]: ", keystoreTargetType, keystoreFilePath);
				} else {
					pwAttemptType = PasswordType.LAST_RESORT;
					ksPassword = new char[] {'c', 'h', 'a', 'n', 'g', 'e', 'i', 't'};
				}
			} else {
				if (console != null) {
					ksPassword = console.readPassword("Incorrect password!\nEnter password for %s KeyStore [%s]: ", keystoreTargetType, keystoreFilePath);
				} else {
					throw wrongPasswordException;
				}
			}
			try (FileInputStream fis = new FileInputStream(keystoreFile)) {
				keystore.load(fis, ksPassword);
			} catch (IOException ex) {
				Throwable cause = ex.getCause();
				if (cause != null && cause instanceof UnrecoverableKeyException) {
					if (PasswordType.DEFAULT.equals(pwAttemptType)) {
						triedDefaultPassword = true;
						continue;
					}
					wrongPasswordException = ex;
					continue;
				}
				throw ex;
			} finally {
				if (ksPassword != null && ksPassword.length > 0) {
					Arrays.fill(ksPassword, ' ');
				}
			}
			break;
		}
		String alias;
		boolean isCert;
		//boolean isKey;
		KeyStoreEntry entry;
		String hash;
		for (Enumeration<String> enu = keystore.aliases(); enu.hasMoreElements();) {
			alias = enu.nextElement();
			entry = null;
			hash = null;
			isCert = keystore.isCertificateEntry(alias);
			//isKey = keystore.isKeyEntry(alias);
			try {
				if (isCert) {
					Certificate cert = keystore.getCertificate(alias);
					entry = new KeyStoreEntry(alias, cert);
					hash = toHexString(sha512.digest(cert.getEncoded()));
					//} else if (isKey) {
					//Key key = keystore.getKey(alias, ksPassword);
					//entry = new KeyStoreEntry(alias, key);
					//hash = toHexString(sha512.digest(key.getEncoded()));
				}
			} catch (CertificateEncodingException ex) {
				Logger.getLogger(Main.class.getName()).log(Level.SEVERE, null, ex);
			}
			if (entry != null) {
				byHash.put(hash, entry);
			}
		}
		return byHash;
	}

	private static String toHexString(byte[] bytes) {
		return toHexString(bytes, false);
	}

	private static String toHexString(byte[] bytes, boolean separator) {
		StringBuilder sb = new StringBuilder((separator ? (bytes.length * 3) - 1 : (bytes.length * 2)));
		for (int i = 0, b; i < bytes.length; i++) {
			b = bytes[i];
			b &= 0xff;
			if (separator && i > 0) {
				sb.append(' ');
			}
			sb.append(HEXDIGITS[b >> 4]);
			sb.append(HEXDIGITS[b & 15]);
		}
		return sb.toString();
	}

	private static String getFilePath(File file) {
		if (file == null) {
			throw new NullPointerException();
		}
		String filePath;
		try {
			filePath = file.getCanonicalPath();
		} catch (IOException ex) {
			filePath = file.getAbsolutePath();
		}
		return filePath;
	}

	public static enum PasswordType {
		ARGUMENT,
		DEFAULT,
		CONSOLE,
		LAST_RESORT
	}
}
