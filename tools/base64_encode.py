from collections.abc import Generator
from typing import Any

from dify_plugin import Tool
from dify_plugin.entities.tool import ToolInvokeMessage

# 从 utils 文件导入我们的核心逻辑函数
from utils.helpers import encode_base64

class Base64EncodeTool(Tool):
    def _invoke(self, tool_parameters: dict[str, Any]) -> Generator[ToolInvokeMessage, None, None]:
        """
        Invokes the Base64 encoding tool.
        """
        input_string = tool_parameters.get('input_string', '')
        if not input_string:
            yield self.create_text_message("Error: Input string is required.")
            return

        try:
            encoded_result = encode_base64(input_string)
            yield self.create_text_message(f"Base64 Encoded: {encoded_result}")
            yield self.create_variable_message("encoded_string", encoded_result)
        except Exception as e:
            yield self.create_text_message(f"An error occurred: {str(e)}")