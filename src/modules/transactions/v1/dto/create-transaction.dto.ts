import { ApiProperty, ApiPropertyOptional } from '@nestjs/swagger';
import { IsIn, IsOptional, IsString, Matches, MaxLength } from 'class-validator';
import { CLIENT_ID_PATTERN, STATE_PATTERN } from '@common/constants/validation.constants';

export class CreateTransactionDto {
  @ApiProperty({ example: 'rms-web-prod' })
  @Matches(CLIENT_ID_PATTERN)
  client_id: string;

  @ApiProperty({ example: 'b1c9f0d2a7e84f6c', description: 'BU-generated CSRF state, echoed back unchanged' })
  @Matches(STATE_PATTERN)
  state: string;

  @ApiPropertyOptional({ example: 'https://rms.example.com', description: 'Parent origin; must exactly match a registered embed origin' })
  @IsOptional()
  @IsString()
  @MaxLength(512)
  origin?: string;

  @ApiPropertyOptional({ description: 'Selects one of the registered callback URIs' })
  @IsOptional()
  @IsString()
  @MaxLength(2048)
  redirect_uri?: string;

  @ApiPropertyOptional({ enum: ['embed', 'page'], default: 'embed' })
  @IsOptional()
  @IsIn(['embed', 'page'])
  display?: 'embed' | 'page';
}
