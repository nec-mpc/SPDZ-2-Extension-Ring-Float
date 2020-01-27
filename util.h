#pragma once

static int read_input_line(FILE * input_file, std::string & line)
{
	char buffer[256];
	if(NULL != fgets(buffer, 256, input_file))
	{
		line = buffer;
		return 0;
	}
	else
		return -1;
}
