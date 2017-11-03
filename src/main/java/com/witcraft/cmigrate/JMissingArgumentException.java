package com.witcraft.cmigrate;

import org.apache.commons.cli.MissingArgumentException;
import org.apache.commons.cli.Option;

/**
 *
 * @author Jason Redding
 */
public class JMissingArgumentException extends MissingArgumentException {

	private static final long serialVersionUID = 1L;
	private Option option;

	public JMissingArgumentException(String message) {
		super(message);
	}
	public JMissingArgumentException(Option option) {
		this("Missing argument for option: " + option.getLongOpt());
		this.option = option;
	}
	public JMissingArgumentException(MissingArgumentException ex) {
		this(ex.getOption());
	}

	@Override
	public Option getOption() {
		return this.option;
	}

}
