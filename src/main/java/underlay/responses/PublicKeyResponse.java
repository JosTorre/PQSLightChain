package underlay.responses;

import skipGraph.NodeInfo;

import java.security.PublicKey;

/** Represents a response which returns a PublicKey. */
public class PublicKeyResponse extends GenericResponse {
  public final byte[] result;

  public PublicKeyResponse(byte[] result) {
    this.result = result;
  }

  public static PublicKeyResponse PublicKeyResponseOf(GenericResponse response) {
    return (PublicKeyResponse) response;
  }

}
