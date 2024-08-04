package org.example.todotravel.domain.chat.dto.request;

import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.NoArgsConstructor;

@Getter
@NoArgsConstructor
@AllArgsConstructor
public class ChatRoomUpdateRequestDto {
    private Long roomId;
    private String newRoomName;
}
