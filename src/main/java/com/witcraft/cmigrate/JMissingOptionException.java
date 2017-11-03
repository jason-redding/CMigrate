package com.witcraft.cmigrate;

import java.util.ArrayList;
import java.util.Iterator;
import java.util.List;
import org.apache.commons.cli.MissingOptionException;
import org.apache.commons.cli.Option;
import org.apache.commons.cli.Options;
import org.apache.commons.cli.ParseException;

/**
 *
 * @author Jason Redding
 */
public class JMissingOptionException extends ParseException {

	/**
	 * This exception {@code serialVersionUID}.
	 */
	private static final long serialVersionUID = 1L;

	/**
	 * The list of missing options and groups
	 */
	private List missingOptions;

	/**
	 * Construct a new <code>JMissingSelectedException</code> with the specified
	 * detail message.
	 *
	 * @param message the detail message
	 */
	public JMissingOptionException(String message) {
		super(message);
	}

	/**
	 * Constructs a new <code>JMissingSelectedException</code> with the specified
	 * list of missing options.
	 *
	 * @param missingOptions the list of missing options and groups
	 *
	 * @since 1.2
	 */
	public JMissingOptionException(List missingOptions) {
		this(createMessage(missingOptions));
		this.missingOptions = missingOptions;
	}

	public JMissingOptionException(Options options, MissingOptionException ex) {
		this(ensureOptionsList(options, ex.getMissingOptions()));
	}

	/**
	 * Returns the list of options or option groups missing in the command line
	 * parsed.
	 *
	 * @return the missing options, consisting of String instances for simple
	 * options, and OptionGroup instances for required option groups.
	 *
	 * @since 1.2
	 */
	public List getMissingOptions() {
		return missingOptions;
	}
	
	private static List<Option> ensureOptionsList(Options options, List<?> missingOptions) {
		List<Option> list = new ArrayList<>();
		String itemText;
		for (Object item : missingOptions) {
			if (item instanceof String) {
				itemText = (String)item;
				if (options.hasOption(itemText)) {
					item = options.getOption(itemText);
				}
			}
			if (item instanceof Option) {
				list.add((Option)item);
			}
		}
		return list;
	}

	/**
	 * Build the exception message from the specified list of options.
	 *
	 * @param missingOptions the list of missing options and groups
	 *
	 * @since 1.2
	 */
	private static String createMessage(List<?> missingOptions) {
		Object item;
		StringBuilder buf = new StringBuilder("Missing required option");
		buf.append(missingOptions.size() == 1 ? "" : "s");
		buf.append(": ");

		Iterator<?> it = missingOptions.iterator();
		while (it.hasNext()) {
			item = it.next();
			if (item instanceof Option) {
				buf.append(((Option)item).getLongOpt());
			} else {
				buf.append(item);
			}
			if (it.hasNext()) {
				buf.append(", ");
			}
		}
		return buf.toString();
	}
}
