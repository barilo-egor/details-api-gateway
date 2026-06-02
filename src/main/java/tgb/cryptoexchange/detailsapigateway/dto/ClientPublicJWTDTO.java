package tgb.cryptoexchange.detailsapigateway.dto;

import lombok.Builder;
import lombok.Data;

@Data
@Builder
public class ClientPublicJWTDTO {

    private String jwtKey;

}
