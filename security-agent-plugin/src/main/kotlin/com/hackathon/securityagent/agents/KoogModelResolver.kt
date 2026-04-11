package com.hackathon.securityagent.agents

import ai.koog.prompt.executor.clients.openai.OpenAIModels

object KoogModelResolver {
    fun resolve(modelName: String) =
        when (modelName.trim().lowercase()) {
            "gpt-4o" -> OpenAIModels.Chat.GPT4o
            "gpt-4o-mini" -> OpenAIModels.Chat.GPT4oMini
            "gpt-4.1" -> OpenAIModels.Chat.GPT4_1
            "gpt-4.1-mini" -> OpenAIModels.Chat.GPT4_1Mini
            "gpt-4.1-nano" -> OpenAIModels.Chat.GPT4_1Nano
            "o3" -> OpenAIModels.Chat.O3
            "o3-mini" -> OpenAIModels.Chat.O3Mini
            "o4-mini" -> OpenAIModels.Chat.O4Mini
            "gpt-5" -> OpenAIModels.Chat.GPT5
            "gpt-5-mini" -> OpenAIModels.Chat.GPT5Mini
            "gpt-5-nano" -> OpenAIModels.Chat.GPT5Nano
            "gpt-5-codex" -> OpenAIModels.Chat.GPT5Codex
            "gpt-5-pro" -> OpenAIModels.Chat.GPT5Pro
            "gpt-5.1" -> OpenAIModels.Chat.GPT5_1
            "gpt-5.1-codex" -> OpenAIModels.Chat.GPT5_1Codex
            "gpt-5.2" -> OpenAIModels.Chat.GPT5_2
            "gpt-5.2-pro" -> OpenAIModels.Chat.GPT5_2Pro
            "gpt-5.3-codex" -> OpenAIModels.Chat.GPT5_3Codex
            "gpt-5.4" -> OpenAIModels.Chat.GPT5_4
            "gpt-5.4-pro" -> OpenAIModels.Chat.GPT5_4Pro
            else -> OpenAIModels.Chat.GPT4_1Mini
        }
}
