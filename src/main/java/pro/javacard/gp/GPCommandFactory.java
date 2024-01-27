/*
 * gpj - Global Platform for Java SmartCardIO
 *
 * Copyright (C) 2009 Wojciech Mostowski, woj@cs.ru.nl
 * Copyright (C) 2009 Francois Kooman, F.Kooman@student.science.ru.nl
 * Copyright (C) 2014 Martin Paljak, martin@martinpaljak.net
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 3.0 of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA
 *
 */

package pro.javacard.gp;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.util.ArrayList;
import java.util.List;

import javax.smartcardio.CommandAPDU;

import apdu4j.ISO7816;
import pro.javacard.gp.GPRegistryEntry.Kind;
import pro.javacard.gp.GlobalPlatform.GPSpec;

/**
 * The main Global Platform class. Provides most of the Global Platform
 * functionality for managing GP compliant smart cards.
 */
public class GPCommandFactory {

	// Implementation details
	private static final byte CLA_GP = (byte) 0x80;
	private static final byte INS_INITIALIZE_UPDATE = (byte) 0x50;
	private static final byte INS_INSTALL = (byte) 0xE6;
	private static final byte INS_LOAD = (byte) 0xE8;
	private static final byte INS_DELETE = (byte) 0xE4;
	private static final byte INS_GET_STATUS = (byte) 0xF2;
	private static final byte INS_SET_STATUS = (byte) 0xF0;
	private static final byte INS_PUT_KEY = (byte) 0xD8;


	public static final int defaultLoadSize = 255;

	public GPCommandFactory() {

	}

	public CommandAPDU createSelectAPDU(AID sdAID)
	{
		// Try to select ISD without giving the sdAID
		CommandAPDU command = null;
		if (sdAID == null ) {
			command = new CommandAPDU(ISO7816.CLA_ISO7816,
					ISO7816.INS_SELECT, 0x04, 0x00, 256);
		} else {
			command = new CommandAPDU(ISO7816.CLA_ISO7816,
					ISO7816.INS_SELECT, 0x04, 0x00, sdAID.getBytes(), 256);
		}

		return command;

	}

	public CommandAPDU createInstallForLoadAPDU(AID packageAID, AID sdAID,
			int codeLength, byte [] hash)
	{
		if (hash == null)
		{
			hash = new byte[0];
		}

		byte[] loadParams = new byte[] { (byte) 0xEF, 0x04, (byte) 0xC6, 0x02,
				(byte) ((codeLength & 0xFF00) >> 8),
				(byte) (codeLength & 0xFF) };

		ByteArrayOutputStream bo = new ByteArrayOutputStream();

		try {
			bo.write(packageAID.getLength());
			bo.write(packageAID.getBytes());

			if (sdAID != null){
				bo.write(sdAID.getLength());
				bo.write(sdAID.getBytes());
			} else {
				bo.write(0);
			}

			bo.write(hash.length);
			bo.write(hash);

			bo.write(loadParams.length);
			bo.write(loadParams);
			bo.write(0);
		} catch (IOException ioe) {
			throw new RuntimeException(ioe);
		}

		return new CommandAPDU(CLA_GP, INS_INSTALL, 0x02, 0x00,
				bo.toByteArray());

	}

	public CommandAPDU createLoadBlockAPDU(byte [] blockData, int blockIndex,
			boolean isLastBlock)
	{
		return new CommandAPDU(CLA_GP, INS_LOAD, isLastBlock ? 0x80 : 0x00,
				blockIndex, blockData);
	}

	public List<CommandAPDU> createLoadBlockAPDUs(List<byte[]> blocks)
	{
		List<CommandAPDU> commands = new ArrayList<CommandAPDU>();

		for (int i = 0; i < blocks.size(); i++)
		{
			commands.add(createLoadBlockAPDU(blocks.get(i), i,
					(i == (blocks.size() - 1))));
		}

		return commands;
	}

	public CommandAPDU createInstallForInstallAPDU(boolean makeSelectable,
			AID packageAID, AID appletAID, AID instanceAID, byte [] privileges,
			byte[] installParams, byte[] installToken)
	{

		if (instanceAID == null) {
			instanceAID = appletAID;
		}

		if (installParams == null) {
			installParams = new byte[] { (byte) 0xC9, 0x00 };
		}

		if (installToken == null) {
			installToken = new byte[0];
		}

		ByteArrayOutputStream bo = new ByteArrayOutputStream();
		try {
			bo.write(packageAID.getLength());
			bo.write(packageAID.getBytes());

			bo.write(appletAID.getLength());
			bo.write(appletAID.getBytes());

			bo.write(instanceAID.getLength());
			bo.write(instanceAID.getBytes());

			bo.write(privileges.length);
			bo.write(privileges);

			bo.write(installParams.length);
			bo.write(installParams);

			bo.write(installToken.length);
			bo.write(installToken);
		} catch (IOException ioe) {
			throw new RuntimeException(ioe);
		}

		return new CommandAPDU(CLA_GP, INS_INSTALL,
				makeSelectable ? 0x0C : 0x04, 0x00, bo.toByteArray());
	}

	public CommandAPDU createDeleteAIDAPDU(AID aid, boolean deleteDeps)
	{
		ByteArrayOutputStream bo = new ByteArrayOutputStream();
		try {
			bo.write(0x4f);
			bo.write(aid.getLength());
			bo.write(aid.getBytes());
		} catch (IOException ioe) {
			throw new RuntimeException(ioe);
		}

		return new CommandAPDU(CLA_GP, INS_DELETE, 0x00,
				deleteDeps ? 0x80 : 0x00, bo.toByteArray());
	}

	public CommandAPDU createGetStatusAPDU(GPRegistry registry, GPSpec spec,
			Kind kind) {
		return createGetStatusAPDU(registry, spec, kind, null);
	}


	public CommandAPDU createGetStatusAPDU(GPRegistry registry, GPSpec spec,
			Kind kind, byte [] aid) {

		if (spec == GPSpec.OP201) {
			registry.tags = false;
		}

		// By default use tags

		//int p1 = 0x80; // Issuer Security Domain
		int p1 = 0;
		if (kind == Kind.IssuerSecurityDomain) p1 |= 0x80;
		if (kind == Kind.Application) p1 |= 0x40;
		if (kind == Kind.ExecutableLoadFile) p1 |= 0x20;

		int p2 = registry.tags? 0x02 : 0x00;

		byte [] filter = null;
		if (aid != null) {
			filter = new byte[aid.length + 2];
			filter[0] = 0x4F;
			filter[1] = (byte) aid.length;
			System.arraycopy(aid, 0, filter, 2, aid.length);

		} else {
			filter = new byte[] { 0x4F, 0x00 };
		}


		// Issuer security domain
		CommandAPDU cmd = new CommandAPDU(CLA_GP, INS_GET_STATUS, p1, p2, filter);


		return cmd;
	}


}
