package jcifs.smb;

import jcifs.Config;
import jcifs.util.Hexdump;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

/**
 * To filter 0 len updates and for debugging
 */

public class SigningDigest implements SmbConstants
{

	private final Logger logger = LoggerFactory.getLogger(getClass());

	private MessageDigest digest;
	private byte[] macSigningKey;
	private boolean bypass = false;
	private int updates;
	private int signSequence;

	public SigningDigest(byte[] macSigningKey, boolean bypass) throws SmbException
	{
		try
		{
			digest = MessageDigest.getInstance("MD5");
		}
		catch (NoSuchAlgorithmException ex)
		{
			logger.error(ex.getMessage(), ex);
			throw new SmbException("MD5", ex);
		}

		this.macSigningKey = macSigningKey;
		this.bypass = bypass;
		this.updates = 0;
		this.signSequence = 0;

		if (logger.isDebugEnabled())
		{
			Hexdump.hexdumpDebug(logger, "macSigningKey:", macSigningKey, 0, macSigningKey.length);
		}
	}

	public SigningDigest(SmbTransport transport, NtlmPasswordAuthentication auth) throws SmbException
	{
		try
		{
			digest = MessageDigest.getInstance("MD5");
		}
		catch (NoSuchAlgorithmException ex)
		{
			logger.error(ex.getMessage(), ex);
			throw new SmbException("MD5", ex);
		}

		try
		{
			switch (Config.getInt("jcifs.smb.lmCompatibility", 3))
			{
				case 0:
				case 1:
				case 2:
					macSigningKey = new byte[40];
					auth.getUserSessionKey(transport.server.encryptionKey, macSigningKey, 0);
					System.arraycopy(auth.getUnicodeHash(transport.server.encryptionKey),
							0, macSigningKey, 16, 24);
					break;
				case 3:
				case 4:
				case 5:
					macSigningKey = new byte[16];
					auth.getUserSessionKey(transport.server.encryptionKey, macSigningKey, 0);
					break;
				default:
					macSigningKey = new byte[40];
					auth.getUserSessionKey(transport.server.encryptionKey, macSigningKey, 0);
					System.arraycopy(auth.getUnicodeHash(transport.server.encryptionKey),
							0, macSigningKey, 16, 24);
					break;
			}
		}
		catch (Exception ex)
		{
			throw new SmbException("", ex);
		}
		if (logger.isDebugEnabled())
		{
			Hexdump.hexdumpDebug(logger, "LM_COMPATIBILITY=" + Config.getInt("jcifs.smb.lmCompatibility", 3), macSigningKey, 0, macSigningKey.length);
		}
	}

	public void update(byte[] input, int offset, int len)
	{
		if (logger.isDebugEnabled())
		{
			String caption = "update: " + updates + " " + offset + ":" + len;
			Hexdump.hexdumpDebug(logger, caption, input, offset, Math.min(len, 256));
		}
		if (len == 0)
		{
			return; /* CRITICAL */
		}
		digest.update(input, offset, len);
		updates++;
	}

	public byte[] digest()
	{
		byte[] b;

		b = digest.digest();

		if (logger.isDebugEnabled())
		{
			Hexdump.hexdumpDebug(logger, "digest: ", b, 0, b.length);
		}
		updates = 0;

		return b;
	}

	/**
	 * Performs MAC signing of the SMB.  This is done as follows.
	 * The signature field of the SMB is overwritted with the sequence number;
	 * The MD5 digest of the MAC signing key + the entire SMB is taken;
	 * The first 8 bytes of this are placed in the signature field.
	 *
	 * @param data   The data.
	 * @param offset The starting offset at which the SMB header begins.
	 * @param length The length of the SMB data starting at offset.
	 */
	void sign(byte[] data, int offset, int length,
			  ServerMessageBlock request, ServerMessageBlock response)
	{
		request.signSeq = signSequence;
		if (response != null)
		{
			response.signSeq = signSequence + 1;
			response.verifyFailed = false;
		}

		try
		{
			update(macSigningKey, 0, macSigningKey.length);
			int index = offset + ServerMessageBlock.SIGNATURE_OFFSET;
			for (int i = 0; i < 8; i++) data[index + i] = 0;
			ServerMessageBlock.writeInt4(signSequence, data, index);
			update(data, offset, length);
			System.arraycopy(digest(), 0, data, index, 8);
			if (bypass)
			{
				bypass = false;
				System.arraycopy("BSRSPYL ".getBytes(), 0, data, index, 8);
			}
		}
		catch (Exception ex)
		{
			logger.error(ex.getMessage(), ex);
		}
		finally
		{
			signSequence += 2;
		}
	}

	/**
	 * Performs MAC signature verification.  This calculates the signature
	 * of the SMB and compares it to the signature field on the SMB itself.
	 *
	 * @param data     The data.
	 * @param offset   The starting offset at which the SMB header begins.
	 * @param response The length of the SMB data starting at offset.
	 */
	boolean verify(byte[] data, int offset, ServerMessageBlock response)
	{
		update(macSigningKey, 0, macSigningKey.length);
		int index = offset;
		update(data, index, ServerMessageBlock.SIGNATURE_OFFSET);
		index += ServerMessageBlock.SIGNATURE_OFFSET;
		byte[] sequence = new byte[8];
		ServerMessageBlock.writeInt4(response.signSeq, sequence, 0);
		update(sequence, 0, sequence.length);
		index += 8;
		if (response.command == ServerMessageBlock.SMB_COM_READ_ANDX)
		{
			/* SmbComReadAndXResponse reads directly from the stream into separate byte[] b.
			 */
			SmbComReadAndXResponse raxr = (SmbComReadAndXResponse) response;
			int length = response.length - raxr.dataLength;
			update(data, index, length - ServerMessageBlock.SIGNATURE_OFFSET - 8);
			update(raxr.b, raxr.off, raxr.dataLength);
		}
		else
		{
			update(data, index, response.length - ServerMessageBlock.SIGNATURE_OFFSET - 8);
		}
		byte[] signature = digest();
		for (int i = 0; i < 8; i++)
		{
			if (signature[i] != data[offset + ServerMessageBlock.SIGNATURE_OFFSET + i])
			{
				if (logger.isWarnEnabled())
				{
					StringBuilder log = new StringBuilder();
					Hexdump.hexdumpString(log, "signature verification failure", signature, 0, 8);
					Hexdump.hexdumpWarn(logger, log.toString(), data, offset + ServerMessageBlock.SIGNATURE_OFFSET, 8);
				}
				return response.verifyFailed = true;
			}
		}

		return response.verifyFailed = false;
	}

	public String toString()
	{
		return "LM_COMPATIBILITY=" + Config.getInt("jcifs.smb.lmCompatibility", 3) + " MacSigningKey=" + Hexdump.toHexString(macSigningKey, 0, macSigningKey.length);
	}
}

