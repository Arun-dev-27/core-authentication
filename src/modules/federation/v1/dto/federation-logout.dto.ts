import { ApiPropertyOptional } from '@nestjs/swagger';
import { IsOptional, IsString, Matches, MaxLength } from 'class-validator';
import { CLIENT_ID_PATTERN } from '@common/constants/validation.constants';

export class FederationLogoutDto {
  @ApiPropertyOptional({ example: 'rms-web-prod', description: 'Required for browser-initiated logout from an application' })
  @IsOptional()
  @Matches(CLIENT_ID_PATTERN)
  client_id?: string;

  @ApiPropertyOptional({ description: 'The `sid` from the assertion the application received' })
  @IsOptional()
  @IsString()
  @MaxLength(128)
  logout_hint?: string;

  @ApiPropertyOptional({ description: 'Must exactly match a registered post-logout redirect URI' })
  @IsOptional()
  @IsString()
  @MaxLength(2048)
  post_logout_redirect_uri?: string;

  @ApiPropertyOptional()
  @IsOptional()
  @IsString()
  @MaxLength(512)
  state?: string;

  @ApiPropertyOptional({ description: 'Service-initiated only: revoke every session of this user' })
  @IsOptional()
  @Matches(/^[A-Za-z0-9._-]{1,64}$/)
  its_id?: string;

  @ApiPropertyOptional({ description: 'Service-initiated only: revoke this session' })
  @IsOptional()
  @IsString()
  @MaxLength(128)
  sid?: string;
}
