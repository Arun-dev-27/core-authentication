import { ApiProperty, ApiPropertyOptional } from '@nestjs/swagger';
import { IsIn, IsOptional, Matches } from 'class-validator';
import { TRANSACTION_ID_PATTERN } from '@common/constants/validation.constants';

export class PortalLogoutDto {
  @ApiProperty()
  @Matches(TRANSACTION_ID_PATTERN)
  transaction_id: string;

  @ApiPropertyOptional({ enum: ['session', 'federation'], default: 'session' })
  @IsOptional()
  @IsIn(['session', 'federation'])
  scope?: 'session' | 'federation';
}
